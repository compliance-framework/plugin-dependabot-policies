package medium_vulnerabilities_count

import future.keywords.in

violation[{}] if {
	# Build a set of alerts that are open and with a medium severity.
	open_alerts := [alert |
		some alert in input.alerts
		alert.state == "open"
		alert.security_vulnerability.severity == "medium"
	]

	count(open_alerts) >= 5
}

title := "Limit amount of medium vulnerabilities"
description := `Medium severity vulnerabilities should be kept within 
 				reasonable limits to avoid a wide footprint of risk`
