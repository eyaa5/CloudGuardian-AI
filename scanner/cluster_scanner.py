import subprocess
import yaml


def run_kubectl(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=True
    )

    if result.returncode != 0:
        print("kubectl command failed")
        print(result.stderr)
        return None

    return result.stdout


pods_yaml = run_kubectl("kubectl get pods -A -o yaml")

if pods_yaml:
    data = yaml.safe_load(pods_yaml)
    pods = data.get("items", [])

    print("=" * 50)
    print("CloudGuardian AI Cluster Report")
    print("=" * 50)

    print(f"Total Pods: {len(pods)}")
    print()

    healthy_pods = 0
    unhealthy_pods = 0
    security_warnings = 0

    for pod in pods:

        name = pod["metadata"]["name"]
        namespace = pod["metadata"]["namespace"]
        status = pod["status"]["phase"]

        print(f"Pod Name : {name}")
        print(f"Namespace: {namespace}")
        print(f"Status   : {status}")

        if status == "Running":
            print("Health   : HEALTHY")
            healthy_pods += 1

        elif status == "Pending":
            print("Health   : WARNING")
            print("Alert    : Pod is waiting to start")
            unhealthy_pods += 1

        elif status == "Failed":
            print("Health   : CRITICAL")
            print("Alert    : Pod has failed")
            unhealthy_pods += 1

        else:
            print("Health   : WARNING")
            print(f"Alert    : Unexpected status ({status})")
            unhealthy_pods += 1

        containers = pod["spec"].get("containers", [])

        for container in containers:

            image = container.get("image", "unknown")

            print(f"Image    : {image}")

            if ":latest" in image:
                print("Security Warning : Using latest tag")
                security_warnings += 1

        print("-" * 50)

    risk_score = (unhealthy_pods * 20) + (security_warnings * 10)

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

    print()
    print("=" * 50)
    print("Security Analysis")
    print("=" * 50)
    print(f"Cluster Risk Score : {risk_score}/100")
    print(f"Security Status    : {security_status}")
    print(f"Security Warnings  : {security_warnings}")

    print()
    print("=" * 50)
    print("Cluster Summary")
    print("=" * 50)
    print(f"Healthy Pods   : {healthy_pods}")
    print(f"Unhealthy Pods : {unhealthy_pods}")

else:
    print("Could not connect to Kubernetes cluster.")