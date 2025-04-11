package compliance_framework.medium_vulnerabilities

import future.keywords.in

violation[{}] if {
    # Build a set of alerts that are open and with a medium severity.
    open_alerts := [alert |
        alert := input[_]
        alert.state == "open"
        alert.security_vulnerability.severity == "medium"
    ]

    # If there are two or more such alerts, then deny.
    count(open_alerts) >= 2
}

title := "Limit amount of medium vulnerabilities"
description := "Medium severity vulnerabilities should be kept within reasonable limits to avoid a wide footprint of risk"
controls := [
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.6",
    },
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.17",
    },
    {
        "class": "SP800-218",
        "control-id": "RV-1.1",
    },
    {
        "class": "SP800-218",
        "control-id": "RV-2.1",
    },
    {
        "class": "OWASP_DSOMM_3",
        "control-id": "BD-3.6",
    },
    {
        "class": "OWASP_DSOMM_3",
        "control-id": "CO-2.14",
    },
    {
        "class": "OWASP_DSOMM_3",
        "control-id": "TV-5.8",
    },
    {
        "class": "OWASP_DSOMM_3",
        "control-id": "TV-5.10",
    },
    {
        "class": "OWASP_DSOMM_3",
        "control-id": "TV-5.11",
    },
]
