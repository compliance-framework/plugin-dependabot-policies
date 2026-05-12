package vulnerabilities_dismissed_by_security_team_test

import data.vulnerabilities_dismissed_by_security_team

test_security_member_dismissed_vulnerability_ok if {
	count(vulnerabilities_dismissed_by_security_team.violation) == 0 with input as {
		"alerts": [{
			"state": "dismissed",
			"dismissed_at": "2024-01-01T00:00:00Z",
			"dismissed_by": {"login": "jon"},
		}],
		"security_team_members": [{"login": "jon"}],
	}
}

test_no_security_team_dismissed_vulnerability_ok if {
	count(vulnerabilities_dismissed_by_security_team.violation) == 0 with input as {"alerts": [{
		"state": "dismissed",
		"dismissed_at": "2024-01-01T00:00:00Z",
		"dismissed_by": {"login": "jon"},
	}]}
}

test_no_security_team_dismissed_vulnerability_skipped if {
	vulnerabilities_dismissed_by_security_team.skip_reason != "" with input as {"alerts": [{
		"state": "dismissed",
		"dismissed_at": "2024-01-01T00:00:00Z",
		"dismissed_by": {"login": "jon"},
	}]}
}

test_security_team_present_not_skipped if {
	not vulnerabilities_dismissed_by_security_team.skip_reason with input as {
		"alerts": [{
			"state": "dismissed",
			"dismissed_at": "2024-01-01T00:00:00Z",
			"dismissed_by": {"login": "jon"},
		}],
		"security_team_members": [{"login": "jon"}],
	}
}

test_non_security_member_dismissed_vulnerability_violation if {
	count(vulnerabilities_dismissed_by_security_team.violation) == 1 with input as {
		"alerts": [{
			"state": "dismissed",
			"dismissed_at": "2024-01-01T00:00:00Z",
			"dismissed_by": {"login": "michael"},
		}],
		"security_team_members": [{"login": "jon"}],
	}
}

test_empty_security_team_dismissed_vulnerability_violation if {
	count(vulnerabilities_dismissed_by_security_team.violation) == 1 with input as {
		"alerts": [{
			"state": "dismissed",
			"dismissed_at": "2024-01-01T00:00:00Z",
			"dismissed_by": {"login": "jon"},
		}],
		"security_team_members": [],
	}
}

test_non_dismissed_alert_no_violation if {
	count(vulnerabilities_dismissed_by_security_team.violation) == 0 with input as {
		"alerts": [{
			"state": "open",
			"dismissed_at": null,
			"dismissed_by": {"login": "michael"},
		}],
		"security_team_members": [{"login": "jon"}],
	}
}
