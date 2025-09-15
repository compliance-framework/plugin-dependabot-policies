package compliance_framework.high_vulnerabilities_dismissal

import data.compliance_framework.utils.time_ext

violation[{}] if {
	working_day_now_ns := time_ext.reduce_day_ns(time.now_ns())
	two_weeks_ago := working_day_now_ns - (14 * time_ext.ONE_DAY_NS)

	# Build a set of high alerts that have been open for more than 5 working days.
	open_alerts := [alert |
		alert := input.alerts[_]
		alert.state == "open"
		alert.security_vulnerability.severity == "high"
		time.parse_rfc3339_ns(alert.created_at) < two_weeks_ago
	]

	# If there are 1 or more such alerts, then deny.
	count(open_alerts) >= 1
}


title := "Limit amount of 'high' vulnerabilities that have not been dismissed within 10 working days"
description := "'High' severity vulnerabilities should be dismissed within two weeks (10 workign days) to avoid a wide footprint of risk"
