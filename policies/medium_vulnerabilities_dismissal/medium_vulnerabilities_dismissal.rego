package medium_vulnerabilities_dismissal

import data.utils.time_ext

violation[{}] if {
	working_day_now_ns := time_ext.reduce_day_ns(time.now_ns())
	one_month_ago := working_day_now_ns - (28 * time_ext.one_day_ns)

	# Check there exists a medium alert that has been open for more than a month
	some alert in input.alerts
	alert.state == "open"
	alert.security_vulnerability.severity == "medium"
	time.parse_rfc3339_ns(alert.created_at) < one_month_ago
}

title := "Limit amount of 'medium' vulnerabilities that have not been dismissed within one month"
description := `
'Medium' severity vulnerabilities should be dismissed within one month (20 working days)
 to avoid a wide footprint of risk
`
