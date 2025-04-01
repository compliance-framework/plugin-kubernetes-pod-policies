package compliance_framework.template.k8s_deny_bad_image_registry

# METADATA
# title: Ensure Container Images are from Approved Registry
# description: Verifies that all container images are pulled from an approved registry to prevent the use of potentially insecure or unauthorized images.
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
        "control-id": "3.3.5", # Identity and Access Management
        "statement-ids": [
            "3", # Ensure that container images are sourced from trusted and approved registries.
        ],
        "control-link": "https://csf.tools/reference/critical-security-controls/version-3/csc-3/csc-3-5/"
    },
    # SAMA IT Governance Framework v1.0
    {
        "class": "SAMA_ITGF_1.0",
        "control-id": "2.3.4", # Software Supply Chain Security
        "statement-ids": [
            "1", # Ensure that only verified and authorized container images are used in production environments.
        ],
        "control-link": "https://www.sama.gov.sa/en-US/RulesInstructions/CyberSecurity/SAMA-IT_Governance_Framework.pdf"
    },
    # SAMA Risk Management Guidelines v1.0
    {
        "class": "SAMA_RMG_1.0",
        "control-id": "4.3.2", # Software Integrity and Trust
        "statement-ids": [
            "2", # Ensure that images are pulled from trusted and secure repositories.
        ],
        "control-link": "https://csf.tools/reference/nist-cybersecurity-framework/v1-1/id/id-1/"
    },
    # SAMA Cloud Computing Framework v1.0
    {
        "class": "SAMA_CCF_1.0",
        "control-id": "3.1.5", # Cloud Security
        "statement-ids": [
            "4", # Ensure secure image sourcing and scanning to protect against malicious containers in cloud environments.
        ],
        "control-link": "https://rulebook.sama.gov.sa/en/cloud-computing-framework#security"
    },
]

violation[{
    "title": "Container image is from an unapproved registry",
    "description": sprintf("Pod '%s' is using an unapproved image: %s", [input.Name, input.Image]),
    "severity": "high"
}] if {
    not startswith(input.Image, "ghcr.io/compliance-framework/")
}
