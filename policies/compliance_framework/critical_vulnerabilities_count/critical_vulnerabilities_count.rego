package compliance_framework.critical_vulnerabilities_count

import future.keywords.in

violation[{}] if {
	# Build a set of alerts that are open and with a critical severity.
	open_alerts := [alert |
		alert := input.alerts[_]
		alert.state == "open"
		alert.security_vulnerability.severity == "critical"
	]

	# If there are 3 or more such alerts, then deny.
	count(open_alerts) >= 2
}


title := "Limit amount of critical vulnerabilities"
description := "Critical severity vulnerabilities should be kept within reasonable limits to avoid a wide footprint of risk"
