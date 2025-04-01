package compliance_framework.template.k8s_pods_deny_elevated_privileges

# METADATA
# title: Ensure Pods Do Not Run Privileged Containers
# description: Verifies that Kubernetes Pods do not run privileged containers to ensure that containers do not have unnecessary elevated privileges which could compromise cluster security.
# custom:
#   controls:
#     - SAMA_CSF_1.0
#     - SAMA_ITGF_1.0
#     - SAMA_RMG_1.0
#     - SAMA_CCF_1.0
#   schedule: "* * * * * *"

controls := [
    # SAMA Cyber Security Framework v1.0
    {
        "class": "SAMA_CSF_1.0",
        "control-id": "3.3.2", # Container Security
        "statement-ids": [
            "1", # Ensure containers are not running with unnecessary privileges.
        ],
        "control-link": "https://csf.tools/reference/critical-security-controls/version-3/csc-3/csc-3-2/"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "2.2.3", # Security and Compliance for Containers
        "statement-ids": [
            "2", # Ensure that container security policies prevent containers from running with elevated privileges.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/SAMA-IT_Governance_Framework.pdf"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "5.2.1", # Container Security
        "statement-ids": [
            "3", # Ensure that privileged container usage is restricted to reduce security risks.
        ],
        "control-link": "https://csf.tools/reference/nist-cybersecurity-framework/v1-1/id/id-1/"
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "2.1.6", # Cloud Container Security
        "statement-ids": [
            "3", # Ensure that containers running in cloud environments follow security best practices by avoiding unnecessary privilege escalation.
        ],
        "control-link": "https://rulebook.sama.gov.sa/en/cloud-computing-framework#security"
    },
]

violation[{
    "title": "Pod is running a privileged container",
    "description": sprintf("Pod '%s' is running a privileged container", [input.Name]),
    "severity": "high"
}] if {
    
    container = input.Spec.Containers[_]
    
    # Ensure SecurityContext is not nil and Privileged is set to true
    container.SecurityContext != null
    container.SecurityContext.Privileged == true
}
