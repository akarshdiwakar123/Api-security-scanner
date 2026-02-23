def test_injection(client, endpoint, report):
    print(f"\nRunning Injection test on {endpoint}")

    payloads = [
        "' OR 1=1 --",
        "' OR 'a'='a",
        "'; DROP TABLE users; --",
        "\" OR 1=1 --"
    ]

    vulnerable = False

    for payload in payloads:
        test_endpoint = f"{endpoint}?id={payload}"
        response = client.get(test_endpoint)

        if response is None:
            continue

        # Detect common SQL error patterns
        error_signatures = [
            "sql syntax",
            "mysql",
            "syntax error",
            "unclosed quotation",
            "database error",
            "sqlite",
            "psql"
        ]

        if response.status_code >= 500:
            vulnerable = True
            break

        for error in error_signatures:
            if error.lower() in response.text.lower():
                vulnerable = True
                break

        if vulnerable:
            break

    if vulnerable:
        print("⚠ Potential SQL Injection vulnerability detected!")
        report.add_finding(
            "SQL Injection",
            "HIGH",
            endpoint,
            "Endpoint appears vulnerable to SQL injection payloads."
        )
    else:
        print("No obvious SQL Injection vulnerability detected.")