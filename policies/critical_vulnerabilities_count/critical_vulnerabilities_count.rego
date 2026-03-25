package critical_vulnerabilities_count

import future.keywords.in

risk_templates := [
  {
    "name": "Excessive open critical vulnerabilities",
    "title": "Repository Has Exceeded the Permitted Number of Open Critical Severity Vulnerabilities",
    "statement": "Two or more open critical severity Dependabot alerts indicates that the repository has accumulated a significant number of unaddressed vulnerabilities with the highest possible impact. Critical vulnerabilities are those where an attacker can achieve full system compromise, remote code execution, or complete data exfiltration. A backlog of critical alerts dramatically increases the probability that the software will be compromised before remediation occurs.",
    "likelihood_hint": "high",
    "impact_hint": "high",
    "violation_ids": ["too_many_critical_vulnerabilities"],
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
      "title": "Reduce open critical vulnerability count below the permitted threshold",
      "description": "Triage all open critical Dependabot alerts and either apply the available patch, replace the vulnerable dependency, or document a formal accepted-risk decision with a scheduled review date.",
      "tasks": [
        { "title": "Review all open critical Dependabot alerts in the repository Security tab" },
        { "title": "Apply patches or update to the minimum non-vulnerable version for each critical alert" },
        { "title": "For alerts where no patch is available, assess exploitability and apply mitigating controls" },
        { "title": "Enable Dependabot security updates to automate future remediation PRs" },
        { "title": "Establish an SLA requiring critical alerts to be resolved within 5 working days" }
      ]
    }
  }
]

violation[{"id": "too_many_critical_vulnerabilities"}] if {
	# Build a set of alerts that are open and with a critical severity.
	open_alerts := [alert |
		some alert in input.alerts
		alert.state == "open"
		alert.security_vulnerability.severity == "critical"
	]

	# If there are 2 or more such alerts, then deny.
	count(open_alerts) >= 2
}

title := "Limit amount of critical vulnerabilities"
description := `
Critical severity vulnerabilities should be kept within
 reasonable limits to avoid a wide footprint of risk
`
