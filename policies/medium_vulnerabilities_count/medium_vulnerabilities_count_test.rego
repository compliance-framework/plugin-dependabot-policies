package medium_vulnerabilities_count_test

import data.medium_vulnerabilities_count

test_too_many_medium_vulnerabilities_fail if {
	count(medium_vulnerabilities_count.violation) == 1 with input as {"alerts": [
		{
			"state": "open",
			"security_vulnerability": {"severity": "medium"},
		},
		{
			"state": "open",
			"security_vulnerability": {"severity": "medium"},
		},
		{
			"state": "open",
			"security_vulnerability": {"severity": "medium"},
		},
		{
			"state": "open",
			"security_vulnerability": {"severity": "medium"},
		},
		{
			"state": "open",
			"security_vulnerability": {"severity": "medium"},
		}, 
	]}
}

test_few_medium_vulnerabilities_pass if {
	count(medium_vulnerabilities_count.violation) == 0 with input as {"alerts": [{
		"state": "open",
		"security_vulnerability": {"severity": "medium"},
	}]}
}
