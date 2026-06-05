import sys
import yaml
import os

report_lines = []


def scan_file(yaml_file):
    risk_score = 0
    findings = []

    with open(yaml_file, "r") as file:
        data = yaml.safe_load(file)

    print("===================================")
    print("CloudGuardian AI Security Report")
    print("===================================")
    print(f"Scanning file: {yaml_file}\n")

    report_lines.append("===================================")
    report_lines.append("CloudGuardian AI Security Report")
    report_lines.append("===================================")
    report_lines.append(f"Scanning file: {yaml_file}")
    report_lines.append("")

    container = data["spec"]["containers"][0]
    security_context = container.get("securityContext", {})

    if not security_context:
        findings.append("[MEDIUM] Missing security context")
        risk_score += 10

    if security_context.get("privileged") is True:
        findings.append("[CRITICAL] Privileged container detected")
        risk_score += 30

    if security_context.get("runAsUser") == 0:
        findings.append("[CRITICAL] Container running as root")
        risk_score += 30

    image = container.get("image", "")
    if ":" not in image:
     findings.append("[MEDIUM] Image has no version tag")
     risk_score += 10

    if image.endswith(":latest"):
        findings.append("[HIGH] Using latest image tag")
        risk_score += 20

    resources = container.get("resources", {})
    limits = resources.get("limits", {})

    if not limits:
        findings.append("[MEDIUM] Missing resource limits")
        risk_score += 10

    for finding in findings:
        print(finding)
        report_lines.append(finding)

    print("\n-----------------------------------")
    print(f"Risk Score: {risk_score}/100")

    report_lines.append("")
    report_lines.append("-----------------------------------")
    report_lines.append(f"Risk Score: {risk_score}/100")

    if risk_score >= 80:
        overall_risk = "CRITICAL"
    elif risk_score >= 50:
        overall_risk = "HIGH"
    elif risk_score >= 20:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    print(f"OVERALL RISK: {overall_risk}")
    print("-----------------------------------\n")

    report_lines.append(f"OVERALL RISK: {overall_risk}")
    report_lines.append("-----------------------------------")
    report_lines.append("")


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