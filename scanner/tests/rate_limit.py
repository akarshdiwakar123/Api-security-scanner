import time


def test_rate_limit(client, endpoint, report):

    request_count = 20
    success_count = 0
    response_times = []

    for i in range(request_count):

        start = time.time()
        response = client.get(endpoint)
        end = time.time()

        # SAFETY CHECK 1: Skip failed requests
        if not response:
            continue

        response_times.append(end - start)

        if response.status_code == 429:
            # Proper rate limiting detected
            return

        if response.status_code == 200:
            success_count += 1

    # If all requests succeeded with no 429
    if success_count == request_count:

        avg_time = sum(response_times) / len(response_times) if response_times else 0

        severity = "MEDIUM"
        description = (
            f"No rate limiting detected after {request_count} rapid requests. "
            f"Average response time: {round(avg_time, 3)} seconds."
        )

        # Detect soft throttling (responses slowing down)
        if response_times and max(response_times) > 2 * min(response_times):
            description += " Possible soft throttling detected."
            severity = "LOW"

        report.add_finding(
            severity,
            "Rate Limiting Missing",
            endpoint,
            description
)
            
        