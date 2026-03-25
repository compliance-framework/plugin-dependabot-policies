package low_vulnerabilities_dismissal

import data.utils.time_ext

risk_templates := [
  {
    "name": "Low vulnerability unresolved beyond SLA",
    "title": "Low Severity Vulnerability Open for More Than 3 Months",
    "statement": "Low severity Dependabot alerts that remain open beyond three months indicate systemic neglect of vulnerability management. While individually low severity, these vulnerabilities can be chained with other weaknesses to achieve higher-impact attacks. Persistent backlogs also signal that the vulnerability management process lacks the capacity or discipline to handle security obligations, creating risk of audit failure.",
    "likelihood_hint": "low",
    "impact_hint": "moderate",
    "violation_ids": ["low_vulnerability_sla_breached"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1395",
        "title": "Dependency on Vulnerable Third-Party Component",
        "url": "https://cwe.mitre.org/data/definitions/1395.html"
      }
    ],
    "remediation": {
      "title": "Resolve or formally accept all low severity vulnerabilities within 3 months",
      "description": "Triage all low severity Dependabot alerts older than three months. Apply available patches, replace deprecated dependencies, or record a formal risk acceptance decision with a scheduled review date.",
      "tasks": [
        { "title": "Identify all low severity alerts open beyond the 3-month SLA" },
        { "title": "Apply patches where available as part of regular dependency maintenance" },
        { "title": "For alerts without patches, document a risk acceptance with a scheduled re-review date" },
        { "title": "Include low severity dependency updates in routine dependency hygiene sprints" },
        { "title": "Configure Dependabot to automatically open PRs for low severity updates" }
      ]
    }
  }
]

violation[{"id": "low_vulnerability_sla_breached"}] if {
	working_day_now_ns := time_ext.reduce_day_ns(time.now_ns())
	three_months_ago := working_day_now_ns - (84 * time_ext.one_day_ns)

	# Check there exists a low alert that has been open for more than 3 months (60 working days).
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
