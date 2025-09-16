package critical_vulnerabilities_count

import future.keywords.in

violation[{}] if {
	# Build a set of alerts that are open and with a critical severity.
	open_alerts := [alert |
		some alert in input.alerts
		alert.state == "open"
		alert.security_vulnerability.severity == "critical"
	]

	# If there are 2 or more such alerts, then deny.
	count(open_alerts) >= 2
}

title := "Limit amount of critical vulnerabilities"
description := `
Critical severity vulnerabilities should be kept within
 reasonable limits to avoid a wide footprint of risk
`
