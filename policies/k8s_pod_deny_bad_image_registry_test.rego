package compliance_framework.template.k8s_deny_bad_image_registry_test

import data.compliance_framework.template.k8s_deny_bad_image_registry

test_allowed_pods if {
    count(k8s_deny_bad_image_registry.violation) == 0 with input as {
        "Name": "nginx-deployment-1", "Image": "ghcr.io/compliance-framework/nginx:v1.0"
    }
}