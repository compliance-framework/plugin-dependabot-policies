package low_vulnerabilities_dismissal

import data.utils.time_ext

violation[{}] if {
	working_day_now_ns := time_ext.reduce_day_ns(time.now_ns())
	three_months_ago := working_day_now_ns - (84 * time_ext.one_day_ns)

	# Check there exists a low alert that has been open for more than 5 working days.
	some alert in input.alerts
	alert.state == "open"
	alert.security_vulnerability.severity == "low"
	time.parse_rfc3339_ns(alert.created_at) < three_months_ago
}

title := "Limit amount of 'low' vulnerabilities that have not been dismissed within three months"
description := `
'Low' severity vulnerabilities should be dismissed within three months (60 working days)
 to avoid a wide footprint of risk
`
