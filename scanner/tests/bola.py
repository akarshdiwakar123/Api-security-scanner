import re
import hashlib
import random
import uuid
import logging
import asyncio
from urllib.parse import urlparse

try:
    import jwt
except ImportError:
    jwt = None

logger = logging.getLogger(__name__)

def detect_id(endpoint):
    uuid_pattern = r'/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'
    match = re.search(uuid_pattern, endpoint)
    if match:
        return {'type': 'uuid', 'value': match.group(1)}

    int_pattern = r'/(\d+)(?:/|$|\?)'
    match = re.search(int_pattern, endpoint)
    if match:
        return {'type': 'integer', 'value': match.group(1)}

    return None

def hash_response(response):
    if not response or not hasattr(response, "text"):
        return None
    return hashlib.md5(response.text.encode('utf-8')).hexdigest()

def decode_token(token):
    if not jwt or not token:
        return None
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded
    except Exception as e:
        logger.debug(f"Failed to decode JWT: {e}")
        return None

def generate_test_ids(id_info):
    test_ids = []
    if not id_info:
        return test_ids
        
    if id_info['type'] == 'integer':
        try:
            base_id = int(id_info['value'])
            test_ids = [str(base_id + 1), str(base_id - 1), str(base_id + random.randint(10, 100))]
            test_ids = [t for t in test_ids if int(t) > 0 or base_id <= 0]
        except ValueError:
            pass
    elif id_info['type'] == 'uuid':
        test_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
        
    return list(set(test_ids))

async def test_bola(client, endpoint, report):
    try:
        original_response = await client.get(endpoint, timeout=10.0)
    except Exception as e:
        logger.error(f"Failed to fetch original endpoint {endpoint}: {e}")
        return

    if not original_response or not hasattr(original_response, "status_code"):
        return
        
    if original_response.status_code not in (200, 201):
        return

    original_hash = hash_response(original_response)
    try:
        original_length = len(original_response.text)
    except AttributeError:
        original_length = 0

    id_info = detect_id(endpoint)
    if not id_info:
        return

    detected_id = id_info['value']
    test_ids = generate_test_ids(id_info)

    token = None
    if hasattr(client, "headers") and isinstance(client.headers, dict):
        auth_header = client.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")

    jwt_data = decode_token(token)
    
    is_admin = False
    if jwt_data:
        roles = jwt_data.get("role", "") or jwt_data.get("roles", [])
        roles_str = str(roles).lower()
        if "admin" in roles_str or "superuser" in roles_str or "system" in roles_str:
            is_admin = True

    # Async Request Coroutine
    async def fetch_modified(test_id):
        if id_info['type'] == 'integer':
            pattern = rf'(?<=[/])({detected_id})(?=[/?]|$)'
            modified_endpoint = re.sub(pattern, test_id, endpoint, count=1)
        else:
            modified_endpoint = endpoint.replace(detected_id, test_id, 1)

        try:
            res = await client.get(modified_endpoint, timeout=10.0)
            return (test_id, modified_endpoint, res)
        except Exception:
            return (test_id, modified_endpoint, None)

    tasks = [fetch_modified(t_id) for t_id in test_ids]
    results = await asyncio.gather(*tasks)

    for test_id, modified_endpoint, test_response in results:
        if not test_response or not hasattr(test_response, "status_code"):
            continue

        if test_response.status_code in (200, 201):
            test_hash = hash_response(test_response)
            try:
                test_length = len(test_response.text)
            except AttributeError:
                test_length = 0
                
            length_diff = abs(test_length - original_length)

            if test_hash != original_hash and length_diff > 5:
                confidence = "MEDIUM"
                severity = "MEDIUM"

                if is_admin:
                    confidence = "LOW"
                    severity = "LOW"
                    details_extra = "User has admin roles, which may permit cross-object access."
                elif jwt_data:
                    user_id = jwt_data.get("user_id") or jwt_data.get("sub") or jwt_data.get("id")
                    if user_id and str(user_id) != test_id:
                        confidence = "HIGH"
                        severity = "HIGH"
                        details_extra = f"JWT user_id ({user_id}) does not match requested object ID."
                    else:
                        details_extra = "JWT present but user_id lack exact mapping."
                else:
                    details_extra = "No JWT context, successfully accessed alternate object."

                if test_length < original_length * 0.1:
                    confidence = "LOW"
                    severity = "LOW"

                description = (
                    f"Accessed object ID {test_id} successfully. "
                    f"Response differs meaningfully from original ID {detected_id}. "
                    f"{details_extra} Confidence: {confidence}"
                )

                try:
                    report.add_finding(
                        severity=severity,
                        title="Broken Object Level Authorization (BOLA)",
                        endpoint=modified_endpoint,
                        description=description
                    )
                except TypeError:
                    report.add_finding(
                        severity,
                        "Broken Object Level Authorization (BOLA)",
                        modified_endpoint,
                        description
                    )
                return # Only log one major BOLA violation per endpoint