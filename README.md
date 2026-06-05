# CloudGuardian AI

## AI-Powered Cloud Security Platform for AWS & Kubernetes

CloudGuardian AI is a cloud-native security platform designed to help organizations identify, assess, and remediate security risks across Kubernetes and AWS environments.

The platform combines automated security scanning, risk scoring, compliance validation, and AI-powered recommendations to improve cloud security posture and reduce operational risk.

---

## Key Features

### Kubernetes Security Analysis

* Kubernetes YAML Manifest Scanning
* Pod Security Validation
* Resource Configuration Checks
* Container Security Assessment
* CIS Kubernetes Benchmark Checks
* RBAC Security Analysis
* Risk Scoring and Reporting

### AWS Security Analysis

* IAM Permission Review
* S3 Bucket Security Checks
* Security Group Analysis
* CloudTrail Configuration Validation
* Encryption Compliance Verification
* AWS Best Practices Assessment

### AI-Powered Security Insights

* Automated Risk Explanations
* Human-Readable Security Reports
* Intelligent Remediation Recommendations
* Security Posture Scoring
* Architecture Security Reviews

---

## Current Capabilities

### Kubernetes YAML Security Scanner

The current implementation analyzes Kubernetes manifests and detects:

* Privileged Containers
* Containers Running as Root
* Missing Security Context
* Missing Resource Limits
* Use of Latest Image Tags
* Missing Image Version Tags
* Missing Image Pull Policies
* Writable Root Filesystems

For each finding, CloudGuardian AI provides:

* Severity Level
* Risk Explanation
* Recommended Fix
* Risk Score Contribution

---

## Example Output

```text
[CRITICAL] Container running as root
Why: Running as root increases the impact of a container compromise.
Fix: Use runAsUser: 1000 and runAsNonRoot: true.

Risk Score: 90/100
OVERALL RISK: CRITICAL
Summary: Immediate action required.
```

---

## Architecture

CloudGuardian AI follows a cloud-native architecture built around AWS services and Kubernetes workloads.

Future versions will leverage:

* Amazon Bedrock
* AWS Lambda
* Amazon DynamoDB
* Amazon S3
* Amazon CloudWatch
* Kubernetes
* Docker

---

## Technology Stack

* Python
* Kubernetes
* Docker
* AWS
* Amazon Bedrock
* AWS Lambda
* Amazon DynamoDB
* Amazon S3
* CloudWatch
* GitHub Actions

---

## Roadmap

### Version 1 – Kubernetes YAML Scanner

* YAML Security Analysis
* Risk Scoring Engine
* Report Generation

### Version 2 – Kubernetes Cluster Scanner

* Live Cluster Security Auditing
* Namespace Analysis
* RBAC Review

### Version 3 – AWS Security Scanner

* IAM Analysis
* S3 Security Review
* Security Group Assessment

### Version 4 – Compliance Engine

* CIS Benchmark Validation
* Security Best Practices Verification

### Version 5 – AI Remediation Engine

* Amazon Bedrock Integration
* AI-Generated Fix Recommendations

### Version 6 – Security Dashboard

* Web Dashboard
* Historical Scan Tracking
* Security Trend Analysis

---

## Project Status

 Active Development

Current Version: Kubernetes YAML Security Scanner

Upcoming Release: Kubernetes Cluster Security Scanner

---

## Author

**Eya Farhat**

Cloud Computing • DevSecOps • AWS • Kubernetes

Building secure cloud-native solutions with automation and AI.
