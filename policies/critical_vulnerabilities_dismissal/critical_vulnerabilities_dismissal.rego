package critical_vulnerabilities_dismissal

import data.utils.time_ext

violation[{}] if {
	working_day_now_ns := time_ext.reduce_day_ns(time.now_ns())
	seven_days_ago := working_day_now_ns - (7 * time_ext.one_day_ns)

	# Check there exists 1 or more critical alerts that have been open for more than 5 working days.
	some alert in input.alerts

	alert.state == "open"
	alert.security_vulnerability.severity == "critical"
	time.parse_rfc3339_ns(alert.created_at) < seven_days_ago
}

title := "Limit amount of critical vulnerabilities within 5 working days"
description := `
Critical severity vulnerabilities should dealth with within
 five working days to avoid a wide footprint of risk`
