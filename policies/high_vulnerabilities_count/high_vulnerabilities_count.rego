package high_vulnerabilities_count

import future.keywords.in

risk_templates := [
  {
    "name": "Excessive open high vulnerabilities",
    "title": "Repository Has Exceeded the Permitted Number of Open High Severity Vulnerabilities",
    "statement": "Three or more open high severity Dependabot alerts indicates that the repository has accumulated a dangerous vulnerability backlog. High severity vulnerabilities can enable significant data exposure, privilege escalation, or service disruption, and should be remediated quickly to reduce the probability of exploitation.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "violation_ids": ["too_many_high_vulnerabilities"],
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
      "title": "Reduce open high vulnerability count below the permitted threshold",
      "description": "Triage all open high severity Dependabot alerts and apply available patches, replace vulnerable dependencies, or document formally accepted risk with compensating controls.",
      "tasks": [
        { "title": "Review all open high severity Dependabot alerts in the repository Security tab" },
        { "title": "Apply patches or update to the minimum non-vulnerable version for each high alert" },
        { "title": "For alerts without patches, assess exploitability and apply compensating controls" },
        { "title": "Enable Dependabot security updates to automate remediation PRs for high severity CVEs" },
        { "title": "Establish an SLA requiring high alerts to be resolved within 10 working days" }
      ]
    }
  }
]

violation[{"id": "too_many_high_vulnerabilities"}] if {
	open_alerts := [alert |
		some alert in input.alerts
		alert.state == "open"
		alert.security_vulnerability.severity == "high"
	]

	count(open_alerts) >= 3
}

title := "Limit amount of high vulnerabilities"
description := `High severity vulnerabilities should be kept within reasonable limits to avoid a wide footprint of risk`
