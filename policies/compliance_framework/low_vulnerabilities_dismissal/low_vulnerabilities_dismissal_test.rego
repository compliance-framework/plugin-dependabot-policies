package compliance_framework.low_vulnerabilities_dismissal


# helper to convert RFC3339 to ns
rfc3339_to_ns(ts) = ns if { ns := time.parse_rfc3339_ns(ts) }

test_over_three_months_violation if {
    now := rfc3339_to_ns("2025-06-20T09:00:00Z")
	count(violation) == 1 with input as {
        "alerts": [
            {
                "state": "open",
                "created_at": "2025-03-19T09:00:00Z",
                "security_vulnerability": {"severity": "low"}
            }
        ]
    } with time.now_ns as now
}

test_one_month_ok if {
    now := rfc3339_to_ns("2025-06-20T09:00:00Z")
	print(now)
	count(violation) == 0 with input as {
        "alerts": [
            {
                "state": "open",
                "created_at": "2025-05-20T09:00:00Z",
                "security_vulnerability": {"severity": "low"}
            }
        ]
    } with time.now_ns as now
}
