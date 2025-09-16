package medium_vulnerabilities_dismissal_test

import data.medium_vulnerabilities_dismissal as mvd

test_over_one_month_violation if {
	now := time.parse_rfc3339_ns("2025-06-20T09:00:00Z")
	count(mvd.violation) == 1 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-05-22T09:00:00Z",
		"security_vulnerability": {"severity": "medium"},
	}]}
		with time.now_ns as now
}

test_two_weeks_ok if {
	now := time.parse_rfc3339_ns("2025-06-20T09:00:00Z")

	count(mvd.violation) == 0 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-06-06T09:00:00Z",
		"security_vulnerability": {"severity": "medium"},
	}]}
		with time.now_ns as now
}
