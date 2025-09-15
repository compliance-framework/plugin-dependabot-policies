package vulnerabilities_dismissed_by_security_team

violation[{}] if {
	input.security_team_members != null

	# Build a set of alerts that have been dismissed by someone not in the security team
	some alert in input.alerts
	in_security_team := [team_member |
		some team_member in input.security_team_members
		alert.dismissed_by.login == team_member.login
	]
	count(in_security_team) == 0
}

title := "Limit unauthorised vulnerability dismissal"
description := "Vulnerabilities should not be dismissed by members who do not belong to a defined security team."
