package compliance_framework.template.k8s_pods_deny_pods_with_host_meta

# METADATA
# title: Ensure Pods Do Not Use Host Network
# description: Verifies that Kubernetes Pods do not use the host network to avoid exposing the host to unnecessary risks and ensure proper isolation of workloads.
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
            "2", # Ensure containers are isolated and not using host network to reduce attack surface.
        ],
        "control-link": "https://csf.tools/reference/critical-security-controls/version-3/csc-3/csc-3-2/"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "2.1.4", # Network Security for Containers
        "statement-ids": [
            "1", # Ensure that container network configurations are isolated and do not expose the host.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/SAMA-IT_Governance_Framework.pdf"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "3.3.5", # Network Isolation
        "statement-ids": [
            "2", # Ensure proper isolation of containers to prevent accidental or intentional exposure to the host.
        ],
        "control-link": "https://csf.tools/reference/nist-cybersecurity-framework/v1-1/id/id-3/"
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "3.2.2", # Cloud Container Security
        "statement-ids": [
            "4", # Ensure cloud-based containers are not running with excessive permissions or host network access.
        ],
        "control-link": "https://rulebook.sama.gov.sa/en/cloud-computing-framework#security"
    },
]

violation[{
    "title": "Pod is using host network",
    "description": sprintf("Pod '%s' is using host network", [input.Name]),
    "severity": "high"
}] if {
    
    container = input.Spec.Containers[_]
    port = container.Ports[_]
    
    port.HostPort != 0
}
