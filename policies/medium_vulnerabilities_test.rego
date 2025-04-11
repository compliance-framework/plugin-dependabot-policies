package compliance_framework.medium_vulnerabilities

test_too_many_medium_vulnerabilities_fail if {
    count(violation) == 1 with input as [
        {
            "state": "open",
            "security_vulnerability": {
                "severity": "medium",
            }
        },
        {
            "state": "open",
            "security_vulnerability": {
                "severity": "medium",
            }
        },
        {
            "state": "open",
            "security_vulnerability": {
                "severity": "medium",
            }
        },
    ]
}

test_few_medium_vulnerabilities_pass if {
    count(violation) == 0 with input as [
        {
            "state": "open",
            "security_vulnerability": {
                "severity": "medium",
            }
        },
    ]
}
