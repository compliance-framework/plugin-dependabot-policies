package vulnerabilities_dismissed_by_security_team_test

import data.vulnerabilities_dismissed_by_security_team

test_security_member_dismissed_vulnerability_ok if {
	count(vulnerabilities_dismissed_by_security_team.violation) == 0 with input as {
		"alerts": [{
			"state": "open",
			"dismissed_by": {"login": "jon"},
		}],
		"security_team_members": [{"login": "jon"}],
	}
}

test_no_security_team_dismissed_vulnerability_ok if {
	count(vulnerabilities_dismissed_by_security_team.violation) == 0 with input as {"alerts": [{
		"state": "open",
		"dismissed_by": {"login": "jon"},
	}]}
}

test_non_security_member_dismissed_vulnerability_violation if {
	count(vulnerabilities_dismissed_by_security_team.violation) == 1 with input as {
		"alerts": [{
			"state": "open",
			"dismissed_by": {"login": "michael"},
		}],
		"security_team_members": [{"login": "jon"}],
	}
}

test_empty_security_team_dismissed_vulnerability_violation if {
	count(vulnerabilities_dismissed_by_security_team.violation) == 1 with input as {
		"alerts": [{
			"state": "open",
			"dismissed_by": {"login": "jon"},
		}],
		"security_team_members": [],
	}
}
