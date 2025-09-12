package compliance_framework.vulnerabilities_dismissed_by_security_team

test_security_member_dismissed_vulnerability_ok if {
	count(violation) == 0 with input as {
		"alerts": [{
			"state": "open",
			"dismissed_by": {"login": "jon"},
		}],
		"security_team_members": [{"login": "jon"}],
	}
}

test_no_security_team_dismissed_vulnerability_ok if {
	count(violation) == 0 with input as {"alerts": [{
		"state": "open",
		"dismissed_by": {"login": "jon"},
	}]}
}

test_non_security_member_dismissed_vulnerability_violation if {
	count(violation) == 1 with input as {
		"alerts": [{
			"state": "open",
			"dismissed_by": {"login": "michael"},
		}],
		"security_team_members": [{"login": "jon"}],
	}
}

test_empty_security_team_dismissed_vulnerability_violation if {
	count(violation) == 1 with input as {
		"alerts": [{
			"state": "open",
			"dismissed_by": {"login": "jon"},
		}],
		"security_team_members": [],
	}
}
