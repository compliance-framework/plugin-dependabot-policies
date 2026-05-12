package high_vulnerabilities_count_test

import data.high_vulnerabilities_count

test_too_many_high_vulnerabilities_fail if {
	count(high_vulnerabilities_count.violation) == 1 with input as {"alerts": [
		{
			"state": "open",
			"security_vulnerability": {"severity": "high"},
		},
		{
			"state": "open",
			"security_vulnerability": {"severity": "high"},
		},
		{
			"state": "open",
			"security_vulnerability": {"severity": "high"},
		},
	]}
}

test_few_high_vulnerabilities_pass if {
	count(high_vulnerabilities_count.violation) == 0 with input as {"alerts": [
		{
			"state": "open",
			"security_vulnerability": {"severity": "high"},
		},
		{
			"state": "open",
			"security_vulnerability": {"severity": "high"},
		},
	]}
}

test_non_open_high_vulnerabilities_ignored if {
	count(high_vulnerabilities_count.violation) == 0 with input as {"alerts": [
		{
			"state": "fixed",
			"security_vulnerability": {"severity": "high"},
		},
		{
			"state": "dismissed",
			"security_vulnerability": {"severity": "high"},
		},
		{
			"state": "auto_dismissed",
			"security_vulnerability": {"severity": "high"},
		},
	]}
}
