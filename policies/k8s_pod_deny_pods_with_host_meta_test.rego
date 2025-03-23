package compliance_framework.template.k8s_pods_deny_pods_with_host_meta

import data.compliance_framework.template.k8s_pods_deny_pods_with_host_meta

test_no_host_network if {
    count(violation) == 0 with input as {
        "Name": "nginx-pod-1",
        "Spec": {
            "Containers": [
                {
                    "Name": "nginx",
                    "Ports": [
                        {
                            "HostPort": 0
                        }
                    ]
                }
            ]
        }
    }
}

test_host_network_used if {
    count(violation) == 1 with input as {
        "Name": "nginx-pod-1",
        "Spec": {
            "Containers": [
                {
                    "Name": "nginx",
                    "Ports": [
                        {
                            "HostPort": 8080
                        }
                    ]
                }
            ]
        }
    }
}

