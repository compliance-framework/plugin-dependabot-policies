package medium_vulnerabilities_count

import future.keywords.in

risk_templates := [
  {
    "name": "Excessive open medium vulnerabilities",
    "title": "Repository Has Exceeded the Permitted Number of Open Medium Severity Vulnerabilities",
    "statement": "Five or more open medium severity Dependabot alerts indicates that the repository has accumulated a significant vulnerability backlog. Medium severity vulnerabilities can still be exploited to achieve data exposure, authentication bypass, or denial of service under the right conditions. A large backlog signals inadequate vulnerability management practices and increases the cumulative attack surface.",
    "likelihood_hint": "moderate",
    "impact_hint": "moderate",
    "violation_ids": ["too_many_medium_vulnerabilities"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-1395",
        "title": "Dependency on Vulnerable Third-Party Component",
        "url": "https://cwe.mitre.org/data/definitions/1395.html"
      }
    ],
    "remediation": {
      "title": "Reduce open medium vulnerability count below the permitted threshold",
      "description": "Triage all open medium Dependabot alerts and prioritize applying patches as part of regular sprint work. Aim to keep the open medium alert count below 5 at all times.",
      "tasks": [
        { "title": "Review all open medium severity Dependabot alerts in the repository Security tab" },
        { "title": "Apply patches or update to non-vulnerable versions as part of regular dependency maintenance" },
        { "title": "Enable Dependabot security updates to automate remediation PRs for medium severity CVEs" },
        { "title": "Incorporate dependency hygiene into regular sprint cycles to prevent backlog accumulation" },
        { "title": "Establish an SLA requiring medium alerts to be resolved within 20 working days" }
      ]
    }
  }
]

violation[{"id": "too_many_medium_vulnerabilities"}] if {
	# Build a set of alerts that are open and with a medium severity.
	open_alerts := [alert |
		some alert in input.alerts
		alert.state == "open"
		alert.security_vulnerability.severity == "medium"
	]

	count(open_alerts) >= 5
}

title := "Limit amount of medium vulnerabilities"
description := `Medium severity vulnerabilities should be kept within 
 				reasonable limits to avoid a wide footprint of risk`
