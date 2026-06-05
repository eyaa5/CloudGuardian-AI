import sys
import yaml
import os
from colorama import Fore, Style, init

init(autoreset=True)

report_lines = []


def clean_text(text):
    return (
        text.replace(Fore.RED, "")
        .replace(Fore.YELLOW, "")
        .replace(Fore.CYAN, "")
        .replace(Fore.GREEN, "")
        .replace(Style.RESET_ALL, "")
    )


def add_finding(findings, severity, title, why, fix, color):
    message = (
        f"{color}[{severity}]{Style.RESET_ALL} {title}\n"
        f"  Why: {why}\n"
        f"  Fix: {fix}"
    )

    findings.append(message)


def scan_file(yaml_file):
    risk_score = 0
    findings = []

    with open(yaml_file, "r") as file:
        data = yaml.safe_load(file)

    container = data["spec"]["containers"][0]
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

    if risk_score >= 80:
        overall_risk = "CRITICAL"
        risk_color = Fore.RED
        summary = "Immediate action required. This workload has serious security risks."
    elif risk_score >= 50:
        overall_risk = "HIGH"
        risk_color = Fore.YELLOW
        summary = "Security issues should be fixed soon."
    elif risk_score >= 20:
        overall_risk = "MEDIUM"
        risk_color = Fore.CYAN
        summary = "Some security improvements are recommended."
    else:
        overall_risk = "LOW"
        risk_color = Fore.GREEN
        summary = "Configuration looks secure."

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
            print(finding)
            print()
            report_lines.append(clean_text(finding))
            report_lines.append("")
    else:
        print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} No security issues detected.")
        report_lines.append("[OK] No security issues detected.")
        report_lines.append("")

    print("-----------------------------------")
    print(f"Risk Score: {risk_score}/100")
    print(f"OVERALL RISK: {risk_color}{overall_risk}{Style.RESET_ALL}")
    print(f"Summary: {summary}")
    print("-----------------------------------\n")

    report_lines.append("-----------------------------------")
    report_lines.append(f"Risk Score: {risk_score}/100")
    report_lines.append(f"OVERALL RISK: {overall_risk}")
    report_lines.append(f"Summary: {summary}")
    report_lines.append("-----------------------------------")
    report_lines.append("")


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

with open("report.txt", "w") as report:
    report.write("\n".join(report_lines))

print("Report saved to report.txt")