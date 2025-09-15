package compliance_framework.low_vulnerabilities_dismissal

import data.compliance_framework.utils.time_ext

violation[{}] if {
	print("Now is ", time.format(time.now_ns()))
	working_day_now_ns := time_ext.reduce_day_ns(time.now_ns())
	print("Checking from ", time.format(working_day_now_ns))
	three_months_ago := working_day_now_ns - (84 * time_ext.ONE_DAY_NS)
	print("They have had two weeks to dismiss from ", time.format(three_months_ago))

	# Build a set of low alerts that have been open for more than 5 working days.
	open_alerts := [alert |
		alert := input.alerts[_]
		alert.state == "open"
		alert.security_vulnerability.severity == "low"
		time.parse_rfc3339_ns(alert.created_at) < three_months_ago
	]

	# If there are 1 or more such alerts, then deny.
	count(open_alerts) >= 1
}

title := "Limit amount of 'low' vulnerabilities that have not been dismissed within three months"
description := "'Low' severity vulnerabilities should be dismissed within three months (60 working days) to avoid a wide footprint of risk"
