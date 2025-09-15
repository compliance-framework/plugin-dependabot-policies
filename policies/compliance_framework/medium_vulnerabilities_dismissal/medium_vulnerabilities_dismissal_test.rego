package compliance_framework.medium_vulnerabilities_dismissal


# helper to convert RFC3339 to ns
rfc3339_to_ns(ts) = ns if { ns := time.parse_rfc3339_ns(ts) }

test_over_one_month_violation if {
    now := rfc3339_to_ns("2025-06-20T09:00:00Z")
	count(violation) == 1 with input as {
        "alerts": [
            {
                "state": "open",
                "created_at": "2025-05-22T09:00:00Z",
                "security_vulnerability": {"severity": "medium"}
            }
        ]
    } with time.now_ns as now
}

test_two_weeks_ok if {
    now := rfc3339_to_ns("2025-06-20T09:00:00Z")
	print(now)
	count(violation) == 0 with input as {
        "alerts": [
            {
                "state": "open",
                "created_at": "2025-06-06T09:00:00Z", 
                "security_vulnerability": {"severity": "medium"}
            }
        ]
    } with time.now_ns as now
}