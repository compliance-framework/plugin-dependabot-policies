package high_vulnerabilities_dismissal

import data.utils.time_ext

violation[{}] if {
	working_day_now_ns := time_ext.reduce_day_ns(time.now_ns())
	two_weeks_ago := working_day_now_ns - (14 * time_ext.one_day_ns)

	some alert in input.alerts
	alert.state == "open"
	alert.security_vulnerability.severity == "high"
	time.parse_rfc3339_ns(alert.created_at) < two_weeks_ago
}

title := "Limit amount of 'high' vulnerabilities that have not been dismissed within 10 working days"
description := `
'High' severity vulnerabilities should be dismissed within two weeks (10 working days)
 to avoid a wide footprint of risk
`
