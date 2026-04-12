import time
import logging
import asyncio
import urllib.parse

try:
    from rich import print
except ImportError:
    pass

logger = logging.getLogger(__name__)

SQL_ERRORS = [
    "syntax error", "sql syntax", "mysql", "unclosed quotation",
    "database error", "sqlite", "psql", "ora-", "pl/sql", "sqlserver",
    "pg_query", "microsoft sql server"
]

PAYLOADS = {
    "error": [
        "'", "\"", "')", "\")", "';--", "' OR 1=1--", "' OR 'a'='a",
        "\" OR \"a\"=\"a", "') OR ('a'='a", "' UNION SELECT NULL--"
    ],
    "time": [
        "'; WAITFOR DELAY '0:0:4'--",
        "'; SELECT pg_sleep(4)--",
        "'; SELECT sleep(4)--"
    ],
    "boolean": [
        (" AND 1=1", " AND 1=2"),
        ("' AND '1'='1", "' AND '1'='2")
    ]
}

def inject_query(endpoint, param, payload):
    parsed = urllib.parse.urlparse(endpoint)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    
    if param in qs:
        qs[param] = [qs[param][0] + payload if qs[param] else payload]
    else:
        qs[param] = [payload]
        
    encoded_qs = urllib.parse.urlencode(qs, doseq=True)
    return f"{parsed.path}?{encoded_qs}"

async def check_boolean(client, original_resp, endpoint, param, true_payload, false_payload):
    ep_true = inject_query(endpoint, param, true_payload)
    ep_false = inject_query(endpoint, param, false_payload)
    
    try:
        # Launch both boolean conditions at once!
        t_task = client.get(ep_true, timeout=10.0)
        f_task = client.get(ep_false, timeout=10.0)
        
        res_t, res_f = await asyncio.gather(t_task, f_task, return_exceptions=True)
        
        if isinstance(res_t, Exception) or isinstance(res_f, Exception):
            return False
            
    except Exception as e:
        logger.debug(f"Boolean SQLi test failed gracefully: {e}")
        return False
        
    if not res_t or not res_f or not original_resp:
        return False
        
    orig_len = len(original_resp.text)
    t_len = len(res_t.text)
    f_len = len(res_f.text)
    
    if abs(t_len - orig_len) < 50 and abs(f_len - orig_len) > 50:
        return True
        
    return False

async def test_injection(client, endpoint, report):
    print(f"\n[bold cyan]Running Advanced SQL Injection scan on {endpoint}[/bold cyan]")
    
    findings = set()
    start_time = time.time()
    try:
        baseline_res = await client.get(endpoint, timeout=10.0)
        baseline_rtt = time.time() - start_time
    except Exception as e:
        logger.error(f"Failed to fetch safe baseline for {endpoint}: {e}")
        return

    if not baseline_res:
        return

    parsed_ep = urllib.parse.urlparse(endpoint)
    qs = urllib.parse.parse_qs(parsed_ep.query)
    
    params_to_test = list(qs.keys())
    if not params_to_test:
        params_to_test = ["id", "search", "query"] 
        
    headers_to_test = {
        "User-Agent": "Mozilla/5.0",
        "X-Forwarded-For": "127.0.0.1"
    }

    async def execute_error_payload(param, payload):
        test_ep = inject_query(endpoint, param, payload)
        try:
            res = await client.get(test_ep, timeout=5.0)
            if not res: return None
            for err in SQL_ERRORS:
                if err in res.text.lower():
                    return ("HIGH", f"Error-based SQLi detected via parameter '{param}'. Stacktrace footprint matched '{err}' after injecting: {payload}", test_ep)
        except Exception:
            pass
        return None

    async def execute_time_payload(param, payload):
        test_ep = inject_query(endpoint, param, payload)
        start = time.time()
        try:
            # We don't want httpx to retry and hold up the pipe on wait blocks
            res = await client.get(test_ep, timeout=8.0)
            rtt = time.time() - start
            if rtt > (baseline_rtt + 3.5):
                return ("HIGH", f"Blind Time-based SQLi detected (Query deliberately delayed by ~ {rtt:.1f}s) via parameter '{param}' with payload: {payload}", test_ep)
        except Exception as e:
            if "timeout" in str(e).lower() and baseline_rtt < 2:
                return ("HIGH", f"Blind Time-based SQLi triggered (Request hung until timeout) via parameter '{param}' with payload: {payload}", test_ep)
        return None
        
    async def execute_header_payload(head_key, head_val, payload):
        bad_headers = {head_key: head_val + payload}
        try:
            res = await client.get(endpoint, headers=bad_headers, timeout=5.0)
            if not res: return None
            for err in SQL_ERRORS:
                if err in res.text.lower():
                    return ("CRITICAL", f"Error-based Header SQLi detected! The '{head_key}' header was reflected maliciously with payload: {payload}", endpoint)
        except Exception:
            pass
        return None

    # We batch tasks so we don't accidentally DOS the server, but still achieve concurrency
    for param in params_to_test:
        
        # 1. Error Based Concurrency
        err_tasks = [execute_error_payload(param, p) for p in PAYLOADS["error"]]
        err_results = await asyncio.gather(*err_tasks)
        for r in err_results:
            if r: findings.add(r)
                
        # 2. Time Based Concurrency
        time_tasks = [execute_time_payload(param, p) for p in PAYLOADS["time"]]
        time_results = await asyncio.gather(*time_tasks)
        for r in time_results:
            if r: findings.add(r)
            
        # 3. Boolean Based Sequential (too dense conditionally for mass-gather normally)
        for true_p, false_p in PAYLOADS["boolean"]:
            val = await check_boolean(client, baseline_res, endpoint, param, true_p, false_p)
            if val:
                 desc = f"Boolean-Inferential SQLi detected via parameter '{param}'. Forced TRUE logic returned native data, while FALSE dropped content."
                 findings.add(("HIGH", desc, inject_query(endpoint, param, "BOOLEAN_INJECTION")))

    # Header Fuzzing Concurrency
    for head_key, head_val in headers_to_test.items():
        header_tasks = [execute_header_payload(head_key, head_val, p) for p in PAYLOADS["error"][:3]]
        head_results = await asyncio.gather(*header_tasks)
        for r in head_results:
            if r: findings.add(r)

    if findings:
        for sev, desc, url in findings:
            print(f"[yellow]⚠ {desc}[/yellow]")
            try:
                report.add_finding(severity=sev, title="SQL Injection", endpoint=url, description=desc)
            except TypeError:
                report.add_finding(sev, "SQL Injection", url, desc)
    else:
         print("[green]✔ No obvious SQL Injection vulnerabilities detected across vectors.[/green]")