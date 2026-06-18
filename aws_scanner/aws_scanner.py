import json
import os
import subprocess

report_lines = []


def add_line(text=""):
    print(text)
    report_lines.append(text)


def run_aws(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=True
    )

    if result.returncode != 0:
        return None, result.stderr

    return result.stdout, None


add_line("=" * 60)
add_line("CloudGuardian AI AWS Security Report")
add_line("=" * 60)

risk_score = 0
warnings = 0
critical_findings = 0

# Test AWS connection
identity_output, error = run_aws("aws sts get-caller-identity")

if error:
    add_line("Could not connect to AWS")
    add_line(error)
else:
    identity = json.loads(identity_output)

    add_line("Connected to AWS")
    add_line(f"Account : {identity.get('Account')}")
    add_line(f"ARN     : {identity.get('Arn')}")
    add_line()

    # IAM users
    add_line("=" * 60)
    add_line("IAM Analysis")
    add_line("=" * 60)

    iam_output, error = run_aws("aws iam list-users")

    if error:
        add_line("IAM scan failed or permission missing.")
        add_line(error)
    else:
        users = json.loads(iam_output).get("Users", [])
        add_line(f"IAM Users Found: {len(users)}")

        for user in users:
            add_line(f"User: {user.get('UserName')}")

    # S3 buckets
    add_line()
    add_line("=" * 60)
    add_line("S3 Analysis")
    add_line("=" * 60)

    s3_output, error = run_aws("aws s3api list-buckets")

    if error:
        add_line("S3 scan failed or permission missing.")
        add_line(error)
    else:
        buckets = json.loads(s3_output).get("Buckets", [])
        add_line(f"S3 Buckets Found: {len(buckets)}")

        if len(buckets) == 0:
            add_line("No S3 buckets found.")
        else:
            for bucket in buckets:
                add_line(f"Bucket: {bucket.get('Name')}")

    # Security Groups
    add_line()
    add_line("=" * 60)
    add_line("Security Group Analysis")
    add_line("=" * 60)

    sg_output, error = run_aws("aws ec2 describe-security-groups")

    if error:
        add_line("Security Group scan failed or permission missing.")
        add_line(error)
    else:
        groups = json.loads(sg_output).get("SecurityGroups", [])
        add_line(f"Security Groups Found: {len(groups)}")

        for group in groups:
            group_name = group.get("GroupName")
            group_id = group.get("GroupId")

            add_line(f"Security Group: {group_name} ({group_id})")

            for permission in group.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")

                    if cidr == "0.0.0.0/0":
                        add_line(f"Warning: Open access detected on ports {from_port}-{to_port}")
                        warnings += 1
                        risk_score += 15

    # CloudTrail
    add_line()
    add_line("=" * 60)
    add_line("CloudTrail Analysis")
    add_line("=" * 60)

    cloudtrail_output, error = run_aws("aws cloudtrail describe-trails")

    if error:
        add_line("CloudTrail scan failed or permission missing.")
        add_line(error)
    else:
        trails = json.loads(cloudtrail_output).get("trailList", [])
        add_line(f"CloudTrail Trails Found: {len(trails)}")

        if len(trails) == 0:
            add_line("Warning: No CloudTrail trails found.")
            warnings += 1
            risk_score += 20
        else:
            for trail in trails:
                add_line(f"Trail: {trail.get('Name')}")

    if risk_score > 100:
        risk_score = 100

    if risk_score == 0:
        status = "SAFE"
    elif risk_score <= 40:
        status = "LOW RISK"
    elif risk_score <= 80:
        status = "MEDIUM RISK"
    else:
        status = "HIGH RISK"

    add_line()
    add_line("=" * 60)
    add_line("AWS Security Summary")
    add_line("=" * 60)
    add_line(f"AWS Risk Score     : {risk_score}/100")
    add_line(f"Security Status    : {status}")
    add_line(f"Security Warnings  : {warnings}")
    add_line(f"Critical Findings  : {critical_findings}")

    add_line()
    add_line("=" * 60)
    add_line("Final Verdict")
    add_line("=" * 60)

    if status == "SAFE":
        add_line("AWS account looks secure based on current checks.")
    elif status == "LOW RISK":
        add_line("AWS account is mostly secure. Review warnings.")
    elif status == "MEDIUM RISK":
        add_line("AWS account needs security improvements.")
    else:
        add_line("AWS account has serious security risks.")

os.makedirs("../reports", exist_ok=True)

with open("../reports/aws_report.txt", "w") as report:
    report.write("\n".join(report_lines))

add_line()
add_line("Report saved to reports/aws_report.txt")