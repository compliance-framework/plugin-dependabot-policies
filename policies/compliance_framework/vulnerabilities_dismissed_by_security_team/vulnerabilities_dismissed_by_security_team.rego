package compliance_framework.vulnerabilities_dismissed_by_security_team

violation[{}] if {
	input.security_team_members != null

	# Build a set of alerts that have been dismissed by someone not in the security team
	dimissed_by_non_security_member := [alert |
		alert := input.alerts[_]
		in_security_team := [member |
			member := input.security_team_members[_]
			alert.dismissed_by.login == member.login
		]

		count(in_security_team) == 0
	]

	# If there are 1 or more such alerts, then deny.
	count(dimissed_by_non_security_member) >= 1
}

title := "Limit unauthorised vulnerability dismissal"
description := "Vulnerabilities should not be dismissed by members who do not belong to a defined security team."
