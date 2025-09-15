package compliance_framework.critical_vulnerabilities_dismissal

import data.compliance_framework.utils.time_ext

violation[{}] if {
	working_day_now_ns := time_ext.reduce_day_ns(time.now_ns())
	seven_days_ago := working_day_now_ns - (7 * time_ext.ONE_DAY_NS)

	# Build a set of critical alerts that have been open for more than 5 working days.
	open_alerts := [alert |
		alert := input.alerts[_]
		alert.state == "open"
		alert.security_vulnerability.severity == "critical"
		time.parse_rfc3339_ns(alert.created_at) < seven_days_ago
	]

	# If there are 1 or more such alerts, then deny.
	count(open_alerts) >= 1
}


title := "Limit amount of critical vulnerabilities within 5 working days"
description := "Critical severity vulnerabilities should dealth with within five working days to avoid a wide footprint of risk"
