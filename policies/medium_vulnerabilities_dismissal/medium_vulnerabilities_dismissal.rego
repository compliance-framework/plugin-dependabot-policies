package medium_vulnerabilities_dismissal

risk_templates := [
  {
    "name": "Medium vulnerability unresolved beyond SLA",
    "title": "Medium Severity Vulnerability Open for More Than 20 Working Days",
    "statement": "A medium severity Dependabot alert remaining open beyond one month (20 working days) indicates a breakdown in the vulnerability triage and remediation process. While medium severity vulnerabilities require more specific conditions to be exploited than critical or high, unpatched medium severity dependencies accumulate over time and can become stepping stones for privilege escalation or data access when combined with other weaknesses.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["medium_vulnerability_sla_breached"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1395",
        "title": "Dependency on Vulnerable Third-Party Component",
        "url": "https://cwe.mitre.org/data/definitions/1395.html"
      }
    ],
    "remediation": {
      "title": "Remediate all medium severity vulnerabilities within 20 working days",
      "description": "Triage and address medium severity Dependabot alerts open beyond the 20-working-day SLA. Incorporate patching into regular sprint cycles and use Dependabot automation to reduce manual burden.",
      "tasks": [
        { "title": "Identify all medium severity alerts open beyond the 20-working-day SLA" },
        { "title": "Apply the minimum patched version as part of the next scheduled sprint" },
        { "title": "Enable Dependabot security updates to automate PR creation for medium severity CVEs" },
        { "title": "Track medium severity alert age in security dashboards to provide early warning before SLA breach" },
        { "title": "Document any risk acceptance decisions for alerts where patches are unavailable" }
      ]
    }
  }
]

one_day_ns := ((24 * 60) * 60) * 1000000000

reduce_day_ns(ns) := ns if {
	day := time.weekday(ns)
	day != "Sunday"
	day != "Saturday"
}

reduce_day_ns(ns) := working_day_ns if {
	day := time.weekday(ns)
	day == "Sunday"
	working_day_ns := ns - (2 * one_day_ns)
}

reduce_day_ns(ns) := working_day_ns if {
	day := time.weekday(ns)
	day == "Saturday"
	working_day_ns := ns - one_day_ns
}

violation[{"id": "medium_vulnerability_sla_breached"}] if {
	working_day_now_ns := reduce_day_ns(time.now_ns())
	one_month_ago := working_day_now_ns - (28 * one_day_ns)

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
