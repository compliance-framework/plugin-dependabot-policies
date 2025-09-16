package critical_vulnerabilities_dismissal_test

import data.critical_vulnerabilities_dismissal

test_over_five_days_violation if {
	now := time.parse_rfc3339_ns("2025-06-20T09:00:00Z")
	count(critical_vulnerabilities_dismissal.violation) == 1 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-06-03T09:00:00Z",
		"security_vulnerability": {"severity": "critical"},
	}]}
		with time.now_ns as now
}

test_one_day_ok if {
	now := time.parse_rfc3339_ns("2025-06-04T09:00:00Z")
	count(critical_vulnerabilities_dismissal.violation) == 0 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-06-03T09:00:00Z", # one week earlier
		"security_vulnerability": {"severity": "critical"},
	}]}
		with time.now_ns as now
}

test_five_days_over_weekend_ok if {
	now := time.parse_rfc3339_ns("2025-09-22T09:00:00Z")
	count(critical_vulnerabilities_dismissal.violation) == 0 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-09-15T09:00:00Z",
		"security_vulnerability": {"severity": "critical"},
	}]}
		with time.now_ns as now
}

test_just_more_than_five_days_violation if {
	now := time.parse_rfc3339_ns("2025-09-22T09:00:00Z")
	count(critical_vulnerabilities_dismissal.violation) == 1 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-09-15T08:59:59Z",
		"security_vulnerability": {"severity": "critical"},
	}]}
		with time.now_ns as now
}

test_alert_over_weekend_ok if {
	now := time.parse_rfc3339_ns("2025-09-29T09:00:00Z")
	count(critical_vulnerabilities_dismissal.violation) == 0 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-09-26T09:00:00Z",
		"security_vulnerability": {"severity": "critical"},
	}]}
		with time.now_ns as now
}

test_alert_over_weekend_marginal_ok if {
	now := time.parse_rfc3339_ns("2025-09-27T09:00:00Z")
	count(critical_vulnerabilities_dismissal.violation) == 0 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-09-21T09:00:00Z",
		"security_vulnerability": {"severity": "critical"},
	}]}
		with time.now_ns as now
}

test_alert_over_weekend_violation if {
	now := time.parse_rfc3339_ns("2025-09-27T09:00:00Z")
	count(critical_vulnerabilities_dismissal.violation) == 1 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-09-18T09:00:00Z",
		"security_vulnerability": {"severity": "critical"},
	}]}
		with time.now_ns as now
}

test_alert_over_weekend_marginal_violation if {
	now := time.parse_rfc3339_ns("2025-09-27T09:00:00Z")
	count(critical_vulnerabilities_dismissal.violation) == 1 with input as {"alerts": [{
		"state": "open",
		"created_at": "2025-09-19T06:00:00Z",
		"security_vulnerability": {"severity": "critical"},
	}]}
		with time.now_ns as now
}
