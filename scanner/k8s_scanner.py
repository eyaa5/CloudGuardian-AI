import sys
import yaml

risk_score = 0

yaml_file = sys.argv[1]

with open(yaml_file, "r") as file:
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
if risk_score >= 80:
    print("OVERALL RISK: CRITICAL")

elif risk_score >= 50:
    print("OVERALL RISK: HIGH")

elif risk_score >= 20:
    print("OVERALL RISK: MEDIUM")

else:
    print("OVERALL RISK: LOW")
print("-----------------------------------")