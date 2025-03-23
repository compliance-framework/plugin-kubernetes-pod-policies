package compliance_framework.template.k8s_pods_deny_elevated_privileges

test_no_privilege if {
    count(violation) == 0 with input as {
        "Name": "nginx-pod-1",
        "Spec": {
            "Containers": [
                {
                    "Name": "nginx",
                    "SecurityContext": {
                        "Privileged": false
                    }
                }
            ]
        }
    }
}

test_privileged_pod if {
    count(violation) == 1 with input as {
        "Name": "nginx-pod-1",
        "Spec": {
            "Containers": [
                {
                    "Name": "nginx",
                    "SecurityContext": {
                        "Privileged": true
                    }
                }
            ]
        }
    }
}

