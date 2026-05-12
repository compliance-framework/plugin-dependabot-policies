package low_vulnerabilities_count

import future.keywords.in

risk_templates := [
  {
    "name": "Excessive open low vulnerabilities",
    "title": "Repository Has Exceeded the Permitted Number of Open Low Severity Vulnerabilities",
    "statement": "Ten or more open low severity Dependabot alerts indicate that the repository has accumulated a broad vulnerability hygiene backlog. Low severity vulnerabilities are individually lower impact, but can be chained with other weaknesses and can signal that dependency maintenance is not being performed consistently.",
    "likelihood_hint": "low",
    "impact_hint": "moderate",
    "violation_ids": ["too_many_low_vulnerabilities"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1395",
        "title": "Dependency on Vulnerable Third-Party Component",
        "url": "https://cwe.mitre.org/data/definitions/1395.html"
      }
    ],
    "remediation": {
      "title": "Reduce open low vulnerability count below the permitted threshold",
      "description": "Triage low severity Dependabot alerts as part of regular dependency hygiene and keep the open backlog below 10 alerts.",
      "tasks": [
        { "title": "Review all open low severity Dependabot alerts in the repository Security tab" },
        { "title": "Apply patches for low severity alerts during routine dependency maintenance" },
        { "title": "Replace deprecated or unmaintained vulnerable dependencies" },
        { "title": "Enable Dependabot security updates and scheduled version updates" },
        { "title": "Track low severity alert backlog in regular maintenance planning" }
      ]
    }
  }
]

open_low_alerts := [alert |
	some alert in input.alerts
	alert.state == "open"
	alert.security_vulnerability.severity == "low"
]

violation[{"id": "too_many_low_vulnerabilities"}] if {
	count(open_low_alerts) >= 10
}

open_low_count := count(open_low_alerts)

title := "Limit amount of low vulnerabilities"
description := sprintf("Open low severity alert count is %d; the policy threshold is fewer than 10 open low severity alerts.", [open_low_count])
