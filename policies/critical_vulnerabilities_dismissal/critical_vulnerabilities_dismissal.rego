package critical_vulnerabilities_dismissal

risk_templates := [
  {
    "name": "Critical vulnerability unresolved beyond SLA",
    "title": "Critical Severity Vulnerability Open for More Than 5 Working Days",
    "statement": "A critical severity Dependabot alert that remains open beyond 5 working days indicates that the organization's vulnerability response SLA is being breached. Critical vulnerabilities represent the highest exploitability and impact ratings. Prolonged exposure gives attackers a larger window to identify and exploit the weakness, particularly for publicly disclosed CVEs where working proof-of-concept exploits may already exist.",
    "likelihood_hint": "high",
    "impact_hint": "high",
    "violation_ids": ["critical_vulnerability_sla_breached"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1395",
        "title": "Dependency on Vulnerable Third-Party Component",
        "url": "https://cwe.mitre.org/data/definitions/1395.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      }
    ],
    "remediation": {
      "title": "Remediate all critical vulnerabilities within 5 working days",
      "description": "Immediately triage and address any critical Dependabot alerts open beyond the 5-working-day SLA. Apply the patched version, replace the dependency, or escalate to a formal risk acceptance with compensating controls.",
      "tasks": [
        { "title": "Identify all critical Dependabot alerts that have exceeded the 5-working-day SLA" },
        { "title": "Apply the minimum patched version or remove the vulnerable dependency" },
        { "title": "If no patch is available, implement compensating controls and document the accepted risk" },
        { "title": "Enable Dependabot security updates to automatically open PRs for future critical CVEs" },
        { "title": "Review and improve the vulnerability triage process to prevent future SLA breaches" }
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

violation[{"id": "critical_vulnerability_sla_breached"}] if {
	working_day_now_ns := reduce_day_ns(time.now_ns())
	seven_days_ago := working_day_now_ns - (7 * one_day_ns)

	# Check there exists 1 or more critical alerts that have been open for more than 5 working days.
	some alert in input.alerts

	alert.state == "open"
	alert.security_vulnerability.severity == "critical"
	time.parse_rfc3339_ns(alert.created_at) < seven_days_ago
}

title := "Limit amount of critical vulnerabilities within 5 working days"
description := `
Critical severity vulnerabilities should be dealt with within
 five working days to avoid a wide footprint of risk`
