package low_vulnerabilities_dismissal_test

import data.low_vulnerabilities_dismissal

test_over_three_months_violation if {
	now := time.parse_rfc3339_ns("2025-06-20T09:00:00Z")
	count(low_vulnerabilities_dismissal.violation) == 1 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-03-19T09:00:00Z",
		"security_vulnerability": {"severity": "low"},
	}]}
		with time.now_ns as now
}

test_one_month_ok if {
	now := time.parse_rfc3339_ns("2025-06-20T09:00:00Z")

	count(low_vulnerabilities_dismissal.violation) == 0 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-05-20T09:00:00Z",
		"security_vulnerability": {"severity": "low"},
	}]}
		with time.now_ns as now
}
