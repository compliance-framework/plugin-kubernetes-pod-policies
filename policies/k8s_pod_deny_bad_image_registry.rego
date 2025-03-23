package compliance_framework.template.k8s_deny_bad_image_registry

violation[{
    "title": "Container image is from an unapproved registry",
    "description": sprintf("Pod '%s' is using an unapproved image: %s", [input.Name, input.Image]),
    "severity": "high"
}] if {
    not startswith(input.Image, "ghcr.io/compliance-framework/")
}
