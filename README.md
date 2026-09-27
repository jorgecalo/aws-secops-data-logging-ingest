# AWS CloudWatch Logs Ingest Estimator for Google SecOps

Estimate how much AWS CloudWatch log data your organization would send to the **Google SecOps** platform. 

The Python script scans every active account within your AWS Organization. For each account it reports the CloudWatch Logs ingestion volume of the **last 30 days** and the CloudWatch Subscription Filters (Log Sinks) configuration, categorized across the 24 official Google SecOps supported AWS log types.

> [!NOTE]
> This is not an official AWS tool. The numbers are an estimate based on CloudWatch metrics and do not replace your AWS invoice or official billing advice.

---

## What gets measured

The script queries the CloudWatch metric `IncomingBytes` in the `AWS/Logs` namespace across all active accounts and enabled AWS regions.

All sizes use decimal units: **1 GB is 1,000,000,000 bytes** and **1 TB is 1,000 GB**, matching Google SecOps ingestion pricing and licensing metrics.

### Supported Google SecOps AWS Log Types (24 total)

**Premium Parsers:**
*   AWS CloudTrail logs
*   AWS EC2 Hosts logs
*   AWS EC2 Instance logs

**Standard Parsers:**
*   AWS API Gateway access logs
*   AWS Aurora logs
*   AWS CloudWatch logs
*   AWS Config logs
*   AWS Control Tower logs
*   AWS Elastic Load Balancing logs
*   AWS Elastic MapReduce logs
*   AWS GuardDuty logs
*   AWS IAM logs
*   AWS Key Management Service logs
*   AWS Macie logs
*   AWS Network Firewall logs
*   AWS RDS logs
*   AWS Route 53 logs
*   AWS S3 server access logs
*   AWS Security Hub logs
*   AWS Session Manager logs
*   AWS VPC flow logs
*   AWS VPC Transit Gateway flow logs
*   AWS VPN logs
*   AWS WAF logs

---

## Required Cross-Account Setup

Because AWS isolates resources by Account, this script is designed to run from your **Management Account** (or a Delegated Administrator account).

The script uses AWS STS to automatically assume the standard `OrganizationAccountAccessRole` in each underlying member account to gather metrics. If your organization uses a custom name for its cross-account administration role, update the `CROSS_ACCOUNT_ROLE_NAME` variable at the top of the Python script.

## Required Permissions

### In the Management Account (running the script):
* `organizations:ListAccounts`
* `sts:AssumeRole`
* `sts:GetCallerIdentity`

### In Member Accounts (attached to `OrganizationAccountAccessRole`):
* `logs:DescribeLogGroups`
* `logs:DescribeSubscriptionFilters`
* `cloudwatch:GetMetricStatistics`
* `ec2:DescribeRegions`

*(Note: The AWS standard `ReadOnlyAccess` managed policy covers all member account requirements.)*

---

## Prerequisites

Python 3.10 or newer is recommended.

```bash
pip install -r requirements.txt
```

Ensure your AWS credentials are configured (e.g. via AWS IAM Identity Center / SSO, environment variables, or `aws configure`).

---

## Run the Script

```bash
python3 aws-secops-data-ingest.py
```

The script asks you to review and accept the terms of the disclaimer before beginning the organization scan.

---

## Output

For each account you get:
* **Total Ingest:** Log ingestion volume of the last 30 days, in decimal GB.
* **Subscription Filters (Log Sinks):** Every active subscription filter, its destination ARN, and filter pattern.

At the end the script prints the **organization totals**, scanned/skipped account counts, metric errors (if any), and a breakdown across all 24 SecOps log categories:

```text
================================================================================
ORGANIZATION TOTALS
================================================================================
Accounts Found:          12
Accounts Scanned:        12
Accounts Skipped:        0
----------------------------------------
TOTAL VOLUME (30 Days):  1.4520 TB
                         (1,452.00 GB)

SECOPS SUPPORTED LOG CATEGORY BREAKDOWN:
--------------------------------------------------------------------------------
  ├─ AWS CloudTrail logs                :   650.2340 GB  ( 44.8%)
  ├─ AWS VPC flow logs                  :   480.1200 GB  ( 33.1%)
  ├─ AWS Elastic Load Balancing logs    :   180.5000 GB  ( 12.4%)
  ├─ AWS GuardDuty logs                 :    85.2000 GB  (  5.9%)
  ├─ AWS WAF logs                       :    45.1000 GB  (  3.1%)
  ...
  └─ Other / Uncategorized              :    10.8460 GB  (  0.7%)
================================================================================
```

📨 **Send the output to your Google Sales representative or Customer Engineer.**

---

## Disclaimer

This script is provided for informational purposes only and is not an official AWS product. You use it at your own risk. The authors are not liable for any errors, omissions, or damages arising from its use. Always refer to your official AWS invoice for exact charges.
