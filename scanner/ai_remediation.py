import os


class AIRemediationEngine:
    def generate_fix(self, finding):
        remediation_database = {
            "IAM Wildcards": {
                "severity": "HIGH",
                "risk": "Wildcard IAM permissions can allow full access to AWS services and resources.",
                "explanation": (
                    "CloudGuardian AI identified overly broad IAM permissions. "
                    "This increases the risk of privilege escalation and unauthorized access."
                ),
                "recommendation": (
                    "Replace wildcard permissions with least-privilege IAM policies. "
                    "Allow only the specific AWS actions and resources required by the workload."
                ),
            },
            "Public S3 Bucket": {
                "severity": "HIGH",
                "risk": "Public S3 buckets may expose sensitive data to unauthorized users.",
                "explanation": (
                    "CloudGuardian AI detected a potential public storage exposure risk. "
                    "Public buckets can lead to accidental data leaks."
                ),
                "recommendation": (
                    "Enable S3 Block Public Access, review bucket policies, "
                    "and allow access only to trusted identities."
                ),
            },
            "Security Group": {
                "severity": "MEDIUM",
                "risk": "Open inbound security group rules can expose cloud resources to the internet.",
                "explanation": (
                    "CloudGuardian AI identified network exposure. "
                    "Open inbound access increases the attack surface of the environment."
                ),
                "recommendation": (
                    "Restrict inbound traffic to trusted IP ranges and close unnecessary ports."
                ),
            },
            "Privileged Container": {
                "severity": "CRITICAL",
                "risk": "Privileged containers can access host resources and increase compromise impact.",
                "explanation": (
                    "CloudGuardian AI detected a high-risk Kubernetes container configuration. "
                    "Privileged mode weakens container isolation."
                ),
                "recommendation": (
                    "Disable privileged mode and use restricted security contexts."
                ),
            },
        }

        return remediation_database.get(
            finding,
            {
                "severity": "LOW",
                "risk": "Unknown security finding.",
                "explanation": (
                    "CloudGuardian AI could not match this finding to a known remediation rule."
                ),
                "recommendation": (
                    "Review the configuration manually and apply security best practices."
                ),
            },
        )


def add_line(report_lines, text=""):
    print(text)
    report_lines.append(text)


def main():
    report_lines = []

    findings = [
        "IAM Wildcards",
        "Public S3 Bucket",
        "Security Group",
        "Privileged Container",
    ]

    engine = AIRemediationEngine()

    add_line(report_lines, "=" * 60)
    add_line(report_lines, "CloudGuardian AI Remediation Report")
    add_line(report_lines, "=" * 60)
    add_line(report_lines)

    for finding in findings:
        result = engine.generate_fix(finding)

        add_line(report_lines, "-" * 60)
        add_line(report_lines, f"Finding: {finding}")
        add_line(report_lines, f"Severity: {result['severity']}")
        add_line(report_lines)

        add_line(report_lines, "Risk:")
        add_line(report_lines, result["risk"])
        add_line(report_lines)

        add_line(report_lines, "AI Explanation:")
        add_line(report_lines, result["explanation"])
        add_line(report_lines)

        add_line(report_lines, "AI Recommendation:")
        add_line(report_lines, result["recommendation"])
        add_line(report_lines)

    os.makedirs("reports", exist_ok=True)

    with open("reports/ai_remediation_report.txt", "w", encoding="utf-8") as report:
        report.write("\n".join(report_lines))

    add_line(report_lines, "=" * 60)
    add_line(report_lines, "Report saved to reports/ai_remediation_report.txt")


if __name__ == "__main__":
    main()