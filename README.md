# AWS CloudWatch Logs data ingestion script for Google SecOps

Calculate the amount of AWS CloudWatch logs data ingestion to be used for the Google SecOps platform. 

This Python script will scan accounts within your AWS Organization and calculate the amount of data used for CloudWatch Logs in the last 30 days. The scan discovers CloudWatch Subscription Filter (Log Sinks) configurations and categorizes ingestion across the following 24 official Google SecOps supported AWS log types: 

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

When the script has run successfully, you will get an overview of the amount of scanned and skipped accounts, a categorized breakdown of the 24 log types, and the total monthly data ingestion for AWS logs within your organization. Account scanning might be limited due to disabled AWS regions or missing cross-account IAM permissions. 

Send the output of the script to your Sales or Customer Engineer.

---

## Required Packages

```bash
pip install boto3
