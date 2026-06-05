import sys
import yaml
import os
from colorama import Fore, Style, init

init(autoreset=True)

report_lines = []

total_files = 0
critical_count = 0
high_count = 0
medium_count = 0


def clean_text(text):
    return (
        text.replace(Fore.RED, "")
        .replace(Fore.YELLOW, "")
        .replace(Fore.CYAN, "")
        .replace(Fore.GREEN, "")
        .replace(Style.RESET_ALL, "")
    )


def add_finding(findings, severity, title, why, fix, color):
    global critical_count, high_count, medium_count

    message = (
        f"{color}[{severity}]{Style.RESET_ALL} {title}\n"
        f"  Why: {why}\n"
        f"  Fix: {fix}"
    )

    findings.append({"severity": severity, "message": message})

    if severity == "CRITICAL":
        critical_count += 1
    elif severity == "HIGH":
        high_count += 1
    elif severity == "MEDIUM":
        medium_count += 1


def get_first_container(data):
    kind = data.get("kind", "")

    if kind == "Pod":
        return data["spec"]["containers"][0]

    if kind == "Deployment":
        return data["spec"]["template"]["spec"]["containers"][0]

    return None


def calculate_risk_level(risk_score):
    if risk_score >= 80:
        return "CRITICAL", Fore.RED, "Immediate action required. This workload has serious security risks."

    if risk_score >= 50:
        return "HIGH", Fore.YELLOW, "Security issues should be fixed soon."

    if risk_score >= 20:
        return "MEDIUM", Fore.CYAN, "Some security improvements are recommended."

    return "LOW", Fore.GREEN, "Configuration looks secure."


def scan_rbac(data, findings):
    risk_score = 0
    rules = data.get("rules", [])

    for rule in rules:
        if "*" in rule.get("verbs", []):
            add_finding(
                findings,
                "HIGH",
                "Wildcard verb detected",
                "The role allows all Kubernetes actions.",
                "Replace '*' with only the required verbs.",
                Fore.YELLOW,
            )
            risk_score += 20

        if "*" in rule.get("resources", []):
            add_finding(
                findings,
                "HIGH",
                "Wildcard resource access",
                "The role can access all Kubernetes resources.",
                "Limit access to specific resources.",
                Fore.YELLOW,
            )
            risk_score += 20

        if "*" in rule.get("apiGroups", []):
            add_finding(
                findings,
                "MEDIUM",
                "Wildcard API group detected",
                "The role applies to all Kubernetes API groups.",
                "Restrict apiGroups to only the required API groups.",
                Fore.CYAN,
            )
            risk_score += 10

    return risk_score


def scan_container(container, findings):
    risk_score = 0

    security_context = container.get("securityContext", {})
    image = container.get("image", "")
    resources = container.get("resources", {})
    limits = resources.get("limits", {})
    image_pull_policy = container.get("imagePullPolicy")

    if not security_context:
        add_finding(
            findings,
            "MEDIUM",
            "Missing security context",
            "The container does not define explicit security settings.",
            "Add a securityContext with runAsNonRoot, runAsUser, and readOnlyRootFilesystem.",
            Fore.CYAN,
        )
        risk_score += 10

    if security_context.get("privileged") is True:
        add_finding(
            findings,
            "CRITICAL",
            "Privileged container detected",
            "The container has almost full access to the host system.",
            "Set privileged to false and avoid elevated container permissions.",
            Fore.RED,
        )
        risk_score += 30

    if security_context.get("runAsUser") == 0:
        add_finding(
            findings,
            "CRITICAL",
            "Container running as root",
            "Running as root increases the impact of a container compromise.",
            "Use a non-root user such as runAsUser: 1000 and runAsNonRoot: true.",
            Fore.RED,
        )
        risk_score += 30

    if security_context.get("runAsNonRoot") is not True:
        add_finding(
            findings,
            "HIGH",
            "runAsNonRoot is not enabled",
            "Kubernetes cannot guarantee that the container runs without root privileges.",
            "Set runAsNonRoot: true in the securityContext.",
            Fore.YELLOW,
        )
        risk_score += 20

    if ":" not in image:
        add_finding(
            findings,
            "MEDIUM",
            "Image has no version tag",
            "Images without tags can lead to unpredictable deployments.",
            "Use a fixed image version such as nginx:1.25 instead of nginx.",
            Fore.CYAN,
        )
        risk_score += 10

    if image.endswith(":latest"):
        add_finding(
            findings,
            "HIGH",
            "Using latest image tag",
            "The latest tag can change over time and introduce unexpected behavior.",
            "Pin the image to a stable version such as nginx:1.25.",
            Fore.YELLOW,
        )
        risk_score += 20

    if not limits:
        add_finding(
            findings,
            "MEDIUM",
            "Missing resource limits",
            "Without CPU and memory limits, one container can consume too many cluster resources.",
            "Add resources.limits for cpu and memory.",
            Fore.CYAN,
        )
        risk_score += 10

    if image_pull_policy is None:
        add_finding(
            findings,
            "MEDIUM",
            "Missing image pull policy",
            "Without an explicit imagePullPolicy, image behavior may be unclear.",
            "Set imagePullPolicy to IfNotPresent or Always depending on your deployment strategy.",
            Fore.CYAN,
        )
        risk_score += 10

    if security_context.get("readOnlyRootFilesystem") is not True:
        add_finding(
            findings,
            "MEDIUM",
            "Root filesystem is writable",
            "A writable root filesystem can allow attackers to modify files inside the container.",
            "Set readOnlyRootFilesystem: true in the securityContext.",
            Fore.CYAN,
        )
        risk_score += 10

    return risk_score


def print_report(yaml_file, findings, risk_score):
    overall_risk, risk_color, summary = calculate_risk_level(risk_score)

    print("===================================")
    print("CloudGuardian AI Security Report")
    print("===================================")
    print(f"Scanning file: {yaml_file}\n")

    report_lines.append("===================================")
    report_lines.append("CloudGuardian AI Security Report")
    report_lines.append("===================================")
    report_lines.append(f"Scanning file: {yaml_file}")
    report_lines.append("")

    if findings:
        for finding in findings:
            print(finding["message"])
            print()
            report_lines.append(clean_text(finding["message"]))
            report_lines.append("")
    else:
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} No security issues detected.")
        report_lines.append("[OK] No security issues detected.")
        report_lines.append("")

    print("-----------------------------------")
    print(f"Findings: {len(findings)}")
    print(f"Risk Score: {risk_score}/100")
    print(f"OVERALL RISK: {risk_color}{overall_risk}{Style.RESET_ALL}")
    print(f"Summary: {summary}")
    print("-----------------------------------\n")

    report_lines.append("-----------------------------------")
    report_lines.append(f"Findings: {len(findings)}")
    report_lines.append(f"Risk Score: {risk_score}/100")
    report_lines.append(f"OVERALL RISK: {overall_risk}")
    report_lines.append(f"Summary: {summary}")
    report_lines.append("-----------------------------------")
    report_lines.append("")


def scan_file(yaml_file):
    global total_files

    total_files += 1
    findings = []
    risk_score = 0

    with open(yaml_file, "r") as file:
        data = yaml.safe_load(file)

    kind = data.get("kind", "")
    metadata = data.get("metadata", {})
    namespace = metadata.get("namespace", "default")

    automount_token = data.get("spec", {}).get(
        "automountServiceAccountToken",
        False,
    )

    if kind == "ServiceAccount":
        if data.get("automountServiceAccountToken", True):
            add_finding(
                findings,
                "HIGH",
                "ServiceAccount token auto-mount enabled",
                "Pods using this service account may automatically receive Kubernetes API credentials.",
                "Set automountServiceAccountToken: false when API access is not required.",
                Fore.YELLOW,
            )
            risk_score += 20

        print_report(yaml_file, findings, risk_score)
        return

    if kind in ["Role", "ClusterRole"]:
        risk_score += scan_rbac(data, findings)
        print_report(yaml_file, findings, risk_score)
        return

    container = get_first_container(data)

    if container is None:
        findings.append(
            {
                "severity": "INFO",
                "message": f"Unsupported Kubernetes object: {kind}",
            }
        )
        print_report(yaml_file, findings, risk_score)
        return

    risk_score += scan_container(container, findings)

    if automount_token is True:
        add_finding(
            findings,
            "HIGH",
            "Service account token automatically mounted",
            "Containers can access Kubernetes API credentials.",
            "Set automountServiceAccountToken: false if API access is not required.",
            Fore.YELLOW,
        )
        risk_score += 20

    if namespace == "default":
        add_finding(
            findings,
            "MEDIUM",
            "Using default namespace",
            "Resources in the default namespace are harder to manage securely.",
            "Create and use a dedicated namespace for workloads.",
            Fore.CYAN,
        )
        risk_score += 10

    print_report(yaml_file, findings, risk_score)


if len(sys.argv) < 2:
    print("Usage: python k8s_scanner.py <yaml-file-or-folder>")
    sys.exit(1)

target_path = sys.argv[1]

if os.path.isfile(target_path):
    yaml_files = [target_path]

elif os.path.isdir(target_path):
    yaml_files = []

    for filename in os.listdir(target_path):
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            yaml_files.append(os.path.join(target_path, filename))

else:
    print("Error: Path not found")
    sys.exit(1)


for yaml_file in yaml_files:
    scan_file(yaml_file)


print("===================================")
print("SCAN SUMMARY")
print("===================================")
print(f"Files Scanned: {total_files}")
print(f"Critical Findings: {critical_count}")
print(f"High Findings: {high_count}")
print(f"Medium Findings: {medium_count}")
print("===================================")

report_lines.append("")
report_lines.append("===================================")
report_lines.append("SCAN SUMMARY")
report_lines.append("===================================")
report_lines.append(f"Files Scanned: {total_files}")
report_lines.append(f"Critical Findings: {critical_count}")
report_lines.append(f"High Findings: {high_count}")
report_lines.append(f"Medium Findings: {medium_count}")
report_lines.append("===================================")

with open("report.txt", "w") as report:
    report.write("\n".join(report_lines))

print("Report saved to report.txt")