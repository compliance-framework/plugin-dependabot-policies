package critical_vulnerabilities_count_test

import data.critical_vulnerabilities_count

test_too_many_critical_vulnerabilities_fail if {
	count(critical_vulnerabilities_count.violation) == 1 with input as {"alerts": [
		{
			"state": "open",
			"security_vulnerability": {"severity": "critical"},
		},
		{
			"state": "open",
			"security_vulnerability": {"severity": "critical"},
		},
	]}
}

test_few_critical_vulnerabilities_pass if {
	count(critical_vulnerabilities_count.violation) == 0 with input as [{
		"state": "open",
		"security_vulnerability": {"severity": "medium"},
	}]
}
