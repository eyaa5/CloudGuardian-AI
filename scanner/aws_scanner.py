import subprocess


def run_aws_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=True
    )

    if result.returncode != 0:
        print("AWS command failed")
        print(result.stderr)
        return None

    return result.stdout


print("=" * 50)
print("CloudGuardian AI AWS Security Report")
print("=" * 50)

identity = run_aws_command("aws sts get-caller-identity")

if identity:
    print("Connected to AWS account")
    print(identity)
else:
    print("Could not connect to AWS")