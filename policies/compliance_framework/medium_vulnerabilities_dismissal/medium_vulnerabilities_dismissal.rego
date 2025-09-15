package compliance_framework.medium_vulnerabilities_dismissal

import data.compliance_framework.utils.time_ext

violation[{}] if {
	print("Now is ", time.format(time.now_ns()))
	working_day_now_ns := time_ext.reduce_day_ns(time.now_ns())
	print("Checking from ", time.format(working_day_now_ns))
	one_month_ago := working_day_now_ns - (28 * time_ext.ONE_DAY_NS)
	print("They have had two weeks to dismiss from ", time.format(one_month_ago))

	# Build a set of medium alerts that have been open for more than 5 working days.
	open_alerts := [alert |
		alert := input.alerts[_]
		alert.state == "open"
		alert.security_vulnerability.severity == "medium"
		time.parse_rfc3339_ns(alert.created_at) < one_month_ago
	]

	# If there are 1 or more such alerts, then deny.
	count(open_alerts) >= 1
}


title := "Limit amount of 'medium' vulnerabilities that have not been dismissed within one month"
description := "'Medium' severity vulnerabilities should be dismissed within one month (20 working days) to avoid a wide footprint of risk"
