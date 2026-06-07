import os
import subprocess
import yaml

report_lines = []


def add_line(text=""):
    print(text)
    report_lines.append(text)


def run_kubectl(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=True
    )

    if result.returncode != 0:
        add_line("kubectl command failed")
        add_line(result.stderr)
        return None

    return result.stdout


pods_yaml = run_kubectl("kubectl get pods -A -o yaml")
clusterroles_yaml = run_kubectl("kubectl get clusterroles -o yaml")

healthy_pods = 0
unhealthy_pods = 0
security_warnings = 0
critical_findings = 0

add_line("=" * 60)
add_line("CloudGuardian AI Cluster Security Report")
add_line("=" * 60)

if pods_yaml:
    data = yaml.safe_load(pods_yaml)
    pods = data.get("items", [])

    add_line(f"Total Pods: {len(pods)}")
    add_line()

    for pod in pods:
        name = pod["metadata"]["name"]
        namespace = pod["metadata"]["namespace"]
        status = pod["status"]["phase"]
        containers = pod["spec"].get("containers", [])

        add_line(f"Pod Name : {name}")
        add_line(f"Namespace: {namespace}")
        add_line(f"Status   : {status}")

        if status == "Running":
            add_line("Health   : HEALTHY")
            healthy_pods += 1
        else:
            add_line("Health   : WARNING")
            add_line(f"Alert    : Pod status is {status}")
            unhealthy_pods += 1

        for container in containers:
            image = container.get("image", "unknown")
            security_context = container.get("securityContext", {})

            add_line(f"Image    : {image}")

            if image.endswith(":latest"):
                add_line("Warning  : Image uses latest tag")
                security_warnings += 1

            if security_context.get("privileged") is True:
                add_line("Critical : Privileged container detected")
                critical_findings += 1

            if security_context.get("runAsUser") == 0:
                add_line("Critical : Container running as root")
                critical_findings += 1

        add_line("-" * 60)

else:
    add_line("Could not retrieve pod data.")


add_line()
add_line("=" * 60)
add_line("RBAC Security Analysis")
add_line("=" * 60)

if clusterroles_yaml:
    rbac_data = yaml.safe_load(clusterroles_yaml)
    clusterroles = rbac_data.get("items", [])

    dangerous_roles = 0

    for role in clusterroles:
        role_name = role["metadata"]["name"]
        rules = role.get("rules", [])

        for rule in rules:
            api_groups = rule.get("apiGroups", [])
            resources = rule.get("resources", [])
            verbs = rule.get("verbs", [])

            if "*" in api_groups or "*" in resources or "*" in verbs:
                add_line(f"Critical : Wildcard RBAC permission detected")
                add_line(f"Role     : {role_name}")
                add_line(f"API      : {api_groups}")
                add_line(f"Resource : {resources}")
                add_line(f"Verbs    : {verbs}")
                add_line("Risk     : This role may grant broad cluster access.")
                add_line("-" * 60)

                dangerous_roles += 1
                critical_findings += 1
                break

    if dangerous_roles == 0:
        add_line("No dangerous RBAC wildcard permissions detected.")

else:
    add_line("Could not retrieve RBAC data.")


risk_score = (
    (unhealthy_pods * 20)
    + (security_warnings * 10)
    + (critical_findings * 15)
)

if risk_score > 100:
    risk_score = 100

if risk_score == 0:
    security_status = "SAFE"
elif risk_score <= 40:
    security_status = "LOW RISK"
elif risk_score <= 80:
    security_status = "MEDIUM RISK"
else:
    security_status = "HIGH RISK"


add_line()
add_line("=" * 60)
add_line("Security Analysis")
add_line("=" * 60)
add_line(f"Cluster Risk Score : {risk_score}/100")
add_line(f"Security Status    : {security_status}")
add_line(f"Security Warnings  : {security_warnings}")
add_line(f"Critical Findings  : {critical_findings}")

add_line()
add_line("=" * 60)
add_line("Cluster Summary")
add_line("=" * 60)
add_line(f"Healthy Pods   : {healthy_pods}")
add_line(f"Unhealthy Pods : {unhealthy_pods}")

add_line()
add_line("=" * 60)
add_line("Final Verdict")
add_line("=" * 60)

if security_status == "SAFE":
    add_line("Cluster is secure.")
elif security_status == "LOW RISK":
    add_line("Cluster is mostly secure. Review warnings.")
elif security_status == "MEDIUM RISK":
    add_line("Cluster requires security attention.")
else:
    add_line("Cluster has serious security risks. Immediate action is recommended.")

os.makedirs("reports", exist_ok=True)

with open("reports/cluster_report.txt", "w") as report:
    report.write("\n".join(report_lines))

add_line()
add_line("Report saved to reports/cluster_report.txt")