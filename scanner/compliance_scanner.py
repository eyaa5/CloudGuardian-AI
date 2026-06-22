import os

report_lines = []

def add_line(text=""):
    print(text)
    report_lines.append(text)

add_line("======================================")
add_line("CloudGuardian AI Compliance Report")
add_line("======================================")

checks = {
    "CloudTrail Enabled": {
        "status": "PASS"
    },

    "IAM Wildcards": {
        "status": "FAIL",
        "severity": "HIGH",
        "risk": "Administrator access to all resources.",
        "recommendation": "Apply least-privilege permissions."
    },

    "Public S3 Buckets": {
        "status": "FAIL",
        "severity": "HIGH",
        "risk": "Public buckets may expose sensitive data.",
        "recommendation": "Disable public access and enable bucket policies."
    },

    "Security Groups": {
        "status": "FAIL",
        "severity": "MEDIUM",
        "risk": "Inbound traffic is open to the internet.",
        "recommendation": "Restrict access to trusted IP addresses."
    }
}

score = 0
for check, details in checks.items():

    status = details["status"]

    add_line(f"{check:<25} {status}")

    if status == "PASS":
        score += 25

    if status == "FAIL":

        add_line("")
        add_line(f"Finding: {check}")

        if "risk" in details:
           add_line("")
           add_line("Risk:")
           add_line(details["risk"])

        if "severity" in details:
            add_line(f"Severity: {details['severity']}")

        if "recommendation" in details:
            add_line("")
            add_line("Recommendation:")
            add_line(details["recommendation"])

        add_line("")

add_line("--------------------------------------")
add_line(f"Compliance Score: {score}%")
add_line("")

if score >= 90:
    add_line("Compliance Status: COMPLIANT")

elif score >= 70:
    add_line("Compliance Status: MOSTLY COMPLIANT")

elif score >= 40:
    add_line("Compliance Status: NEEDS IMPROVEMENT")

else:
    add_line("Compliance Status: NON-COMPLIANT")

os.makedirs("reports", exist_ok=True)

with open("reports/compliance_report.txt", "w", encoding="utf-8") as report:
    report.write("\n".join(report_lines))

add_line()
add_line("Report saved to reports/compliance_report.txt")