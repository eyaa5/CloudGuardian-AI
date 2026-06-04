import yaml

risk_score = 0

with open("../examples/dangerous-pod.yaml", "r") as file:
    data = yaml.safe_load(file)

print("===================================")
print("CloudGuardian AI Security Report")
print("===================================\n")

container = data["spec"]["containers"][0]
security_context = container.get("securityContext", {})
if not security_context:
    print("[MEDIUM] Missing security context")
    risk_score += 10
if security_context.get("privileged") is True:
    print("[CRITICAL] Privileged container detected")
    risk_score += 30

if security_context.get("runAsUser") == 0:
    print("[CRITICAL] Container running as root")
    risk_score += 30

image = container.get("image", "")

if image.endswith(":latest"):
    print("[HIGH] Using latest image tag")
    risk_score += 20

    # Check 4: Missing resource limits
resources = container.get("resources", {})
limits = resources.get("limits", {})

if not limits:
    print("[MEDIUM] Missing resource limits")
    risk_score += 10

print("\n-----------------------------------")
print(f"Risk Score: {risk_score}/100")
print("-----------------------------------")