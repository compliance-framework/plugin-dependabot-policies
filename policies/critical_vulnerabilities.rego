package compliance_framework.critical_vulnerabilities

import future.keywords.in

violation[{}] if {
    # Build a set of alerts that are open and with a medium severity.
    open_alerts := [alert |
        alert := input[_]
        alert.state == "open"
        alert.security_vulnerability.severity == "critical"
    ]

    # If there are 1 or more such alerts, then deny.
    count(open_alerts) >= 1
}

title := "Limit amount of critical vulnerabilities"
description := "Critical severity vulnerabilities should be kept within reasonable limits to avoid a wide footprint of risk"
