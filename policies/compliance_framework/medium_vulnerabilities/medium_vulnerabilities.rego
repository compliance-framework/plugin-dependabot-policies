package compliance_framework.medium_vulnerabilities

import future.keywords.in

violation[{}] if {
	# Build a set of alerts that are open and with a medium severity.
	open_alerts := [alert |
		alert := input.alerts[_]
		alert.state == "open"
		alert.security_vulnerability.severity == "medium"
	]

	# If there are two or more such alerts, then deny.
	count(open_alerts) >= 2
}

title := "Limit amount of medium vulnerabilities"
description := "Medium severity vulnerabilities should be kept within reasonable limits to avoid a wide footprint of risk"
