package high_vulnerabilities_dismissal

import data.utils.time_ext

risk_templates := [
  {
    "name": "High vulnerability unresolved beyond SLA",
    "title": "High Severity Vulnerability Open for More Than 10 Working Days",
    "statement": "A high severity Dependabot alert remaining open beyond 10 working days indicates an SLA breach in the vulnerability remediation process. High severity vulnerabilities can enable significant data exposure, privilege escalation, or service disruption. As public CVE disclosures are indexed by exploit databases and threat actors, delayed remediation substantially increases the probability of exploitation.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "violation_ids": ["high_vulnerability_sla_breached"],
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
      "title": "Remediate all high severity vulnerabilities within 10 working days",
      "description": "Triage and address any high severity Dependabot alerts open beyond the 10-working-day SLA. Apply the patched version, replace the dependency, or escalate to a formal risk acceptance process.",
      "tasks": [
        { "title": "Identify all high severity Dependabot alerts that have exceeded the 10-working-day SLA" },
        { "title": "Apply the minimum patched version or replace the vulnerable dependency" },
        { "title": "If no patch is available, assess exploitability and apply compensating controls" },
        { "title": "Enable Dependabot security updates to automate PR creation for high severity CVEs" },
        { "title": "Review triage and prioritization processes to prevent future SLA breaches" }
      ]
    }
  }
]

violation[{"id": "high_vulnerability_sla_breached"}] if {
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
