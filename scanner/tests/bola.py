import re
import hashlib

try:
    import jwt
except ImportError:
    jwt = None


def detect_id(endpoint):
    match = re.search(r'/(\d+)', endpoint)
    if match:
        return match.group(1)
    return None


def hash_response(response):
    if not response or not hasattr(response, "text"):
        return None
    return hashlib.md5(response.text.encode()).hexdigest()


def decode_token(token):
    if not jwt or not token:
        return None
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded
    except Exception:
        return None


def test_bola(client, endpoint, report):

    original_response = client.get(endpoint)

    # Safety check
    if not original_response or not hasattr(original_response, "status_code"):
        return

    if original_response.status_code != 200:
        return

    original_hash = hash_response(original_response)
    original_length = len(original_response.text)

    detected_id = detect_id(endpoint)
    if not detected_id:
        return

    try:
        detected_id_int = int(detected_id)
    except ValueError:
        return

    test_ids = [
        str(detected_id_int + 1),
        str(detected_id_int - 1)
    ]

    # Extract JWT if exists
    token = None
    if hasattr(client, "headers") and client.headers:
        auth_header = client.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "")

    jwt_data = decode_token(token)

    for test_id in test_ids:

        modified_endpoint = endpoint.replace(
            f"/{detected_id}",
            f"/{test_id}"
        )

        test_response = client.get(modified_endpoint)

        if not test_response or not hasattr(test_response, "status_code"):
            continue

        if test_response.status_code == 200:

            test_hash = hash_response(test_response)
            test_length = len(test_response.text)

            if test_hash != original_hash and test_length != original_length:

                confidence = "MEDIUM"
                severity = "MEDIUM"

                if jwt_data:
                    user_id = jwt_data.get("user_id") or jwt_data.get("sub")
                    if user_id and str(user_id) != test_id:
                        confidence = "HIGH"
                        severity = "HIGH"

                # ✅ CLI-safe add_finding (positional args)
                report.add_finding(
                    severity,
                    "Broken Object Level Authorization (BOLA)",
                    modified_endpoint,
                    f"Accessed object ID {test_id}. "
                    f"Response differs from original ID {detected_id}. "
                    f"Confidence: {confidence}"
                )

                return