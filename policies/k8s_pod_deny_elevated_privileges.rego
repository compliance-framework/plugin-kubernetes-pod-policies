package compliance_framework.template.k8s_pods_deny_elevated_privileges

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
