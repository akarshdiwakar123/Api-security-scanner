def test_cors(client, endpoint, report):
    print(f"\nRunning CORS Misconfiguration test on {endpoint}")

    test_origin = "https://evil.com"

    try:
        response = client.session.get(
            f"{client.base_url}{endpoint}",
            headers={"Origin": test_origin}
        )
    except Exception:
        print("Failed to test CORS.")
        return

    if not response:
        print("No response received.")
        return

    acao = response.headers.get("Access-Control-Allow-Origin")
    acc = response.headers.get("Access-Control-Allow-Credentials")

    vulnerable = False

    # Case 1: Wildcard with credentials
    if acao == "*" and acc == "true":
        vulnerable = True
        description = "CORS allows any origin with credentials enabled."

    # Case 2: Reflecting origin
    elif acao == test_origin:
        vulnerable = True
        description = "CORS reflects arbitrary Origin header."

    else:
        print("No obvious CORS misconfiguration detected.")
        return

    print("⚠ Potential CORS Misconfiguration detected!")

    report.add_finding(
        "CORS Misconfiguration",
        "HIGH",
        endpoint,
        description
    )