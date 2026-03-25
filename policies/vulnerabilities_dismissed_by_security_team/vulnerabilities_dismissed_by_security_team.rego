package vulnerabilities_dismissed_by_security_team

risk_templates := [
  {
    "name": "Vulnerability dismissed by unauthorized member",
    "title": "Dependabot Alert Dismissed by a Member Outside the Security Team",
    "statement": "Allowing any repository contributor to dismiss Dependabot alerts bypasses the security team's oversight of vulnerability acceptance decisions. Dismissals made outside the security team may reflect convenience rather than a genuine security assessment, masking real risk. Unauthorized dismissals can also indicate insider threat activity where a malicious contributor hides a vulnerability they intend to exploit.",
    "likelihood_hint": "moderate",
    "impact_hint": "high",
    "violation_ids": ["dismissed_by_non_security_member"],
    "threat_refs": [
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-284",
        "title": "Improper Access Control",
        "url": "https://cwe.mitre.org/data/definitions/284.html"
      },
      {
        "system": "https://cwe.mitre.org",
        "external_id": "CWE-693",
        "title": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html"
      }
    ],
    "remediation": {
      "title": "Restrict Dependabot alert dismissal to security team members only",
      "description": "Implement a process and tooling controls to ensure that only members of the designated security team can dismiss Dependabot alerts. Re-open all alerts that were dismissed by non-security-team members and have them reviewed.",
      "tasks": [
        { "title": "Identify all Dependabot alerts dismissed by members not in the security team" },
        { "title": "Re-open dismissed alerts and route them for review by the security team" },
        { "title": "Restrict write access to the Security tab to security team members only where possible" },
        { "title": "Implement a policy requiring security team sign-off before any alert dismissal" },
        { "title": "Audit Dependabot alert dismissal activity on a regular basis to detect unauthorized actions" }
      ]
    }
  }
]

violation[{"id": "dismissed_by_non_security_member"}] if {
	input.security_team_members != null

	some alert in input.alerts
	in_security_team := [team_member |
		some team_member in input.security_team_members
		alert.dismissed_by.login == team_member.login
	]

	# Ensure there is no team member that has dismissed an alert who is not part of the security team
	count(in_security_team) == 0
}

title := "Limit unauthorized vulnerability dismissal"
description := "Vulnerabilities should not be dismissed by members who do not belong to a defined security team."
