package low_vulnerabilities_count_test

import data.low_vulnerabilities_count

test_too_many_low_vulnerabilities_fail if {
	count(low_vulnerabilities_count.violation) == 1 with input as {"alerts": [
		{"state": "open", "security_vulnerability": {"severity": "low"}},
		{"state": "open", "security_vulnerability": {"severity": "low"}},
		{"state": "open", "security_vulnerability": {"severity": "low"}},
		{"state": "open", "security_vulnerability": {"severity": "low"}},
		{"state": "open", "security_vulnerability": {"severity": "low"}},
		{"state": "open", "security_vulnerability": {"severity": "low"}},
		{"state": "open", "security_vulnerability": {"severity": "low"}},
		{"state": "open", "security_vulnerability": {"severity": "low"}},
		{"state": "open", "security_vulnerability": {"severity": "low"}},
		{"state": "open", "security_vulnerability": {"severity": "low"}},
	]}
}

test_few_low_vulnerabilities_pass if {
	count(low_vulnerabilities_count.violation) == 0 with input as {"alerts": [
		{"state": "open", "security_vulnerability": {"severity": "low"}},
		{"state": "open", "security_vulnerability": {"severity": "low"}},
		{"state": "open", "security_vulnerability": {"severity": "low"}},
	]}
}

test_non_open_low_vulnerabilities_ignored if {
	count(low_vulnerabilities_count.violation) == 0 with input as {"alerts": [
		{"state": "fixed", "security_vulnerability": {"severity": "low"}},
		{"state": "dismissed", "security_vulnerability": {"severity": "low"}},
		{"state": "auto_dismissed", "security_vulnerability": {"severity": "low"}},
		{"state": "fixed", "security_vulnerability": {"severity": "low"}},
		{"state": "dismissed", "security_vulnerability": {"severity": "low"}},
		{"state": "auto_dismissed", "security_vulnerability": {"severity": "low"}},
		{"state": "fixed", "security_vulnerability": {"severity": "low"}},
		{"state": "dismissed", "security_vulnerability": {"severity": "low"}},
		{"state": "auto_dismissed", "security_vulnerability": {"severity": "low"}},
		{"state": "fixed", "security_vulnerability": {"severity": "low"}},
	]}
}
