package compliance_framework.high_vulnerabilities_dismissal

# helper to convert RFC3339 to ns
rfc3339_to_ns(ts) = ns if { ns := time.parse_rfc3339_ns(ts) }

test_over_two_weeks_violation if {
    now := rfc3339_to_ns("2025-06-20T09:00:00Z")
	count(violation) == 1 with input as {
        "alerts": [
            {
                "state": "open",
                "created_at": "2025-06-03T09:00:00Z",
                "security_vulnerability": {"severity": "high"}
            }
        ]
    } with time.now_ns as now
}

test_one_day_ok if {
    now := rfc3339_to_ns("2025-06-04T09:00:00Z")
	print(now)
	count(violation) == 0 with input as {
        "alerts": [
            {
                "state": "open",
                "created_at": "2025-06-03T09:00:00Z", # one week earlier
                "security_vulnerability": {"severity": "high"}
            }
        ]
    } with time.now_ns as now
}

test_two_weeks_over_weekend_ok if {
    now := rfc3339_to_ns("2025-09-22T09:00:00Z")
	count(violation) == 0 with input as {
        "alerts": [
            {
                "state": "open",
                "created_at": "2025-09-08T09:00:00Z",
                "security_vulnerability": {"severity": "high"}
            }
        ]
    } with time.now_ns as now
}


test_just_more_than_two_weeks_violation if {
    now := rfc3339_to_ns("2025-09-22T09:00:00Z")
	count(violation) == 1 with input as {
        "alerts": [
            {
                "state": "open",
                "created_at": "2025-09-08T08:59:59Z",
                "security_vulnerability": {"severity": "high"}
            }
        ]
    } with time.now_ns as now
}