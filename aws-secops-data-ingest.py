# AWS CloudWatch Logs SecOps Data Ingest calculation script on ORG and Account(s)
# and includes CloudWatch Subscription Filters (Sinks). Period is 30 days time frame. 
# Jorge Liauw Calo - 2026
#
# ==============================================================================
# DISCLAIMER
# ==============================================================================
# This script is provided for informational purposes only and is not an official 
# AWS tool. It is intended to help estimate log ingestion volumes based on 
# CloudWatch metrics for Google SecOps. Please contact your Sales or CE for usage.
#
# BY RUNNING THIS SCRIPT, YOU ACKNOWLEDGE AND AGREE THAT:
# 1. YOU USE THIS SCRIPT AT YOUR OWN RISK.
# 2. THE AUTHOR(S) AND DISTRIBUTORS ARE NOT LIABLE FOR ANY ERRORS, OMISSIONS, 
#    OR DAMAGES (DIRECT, INDIRECT, OR CONSEQUENTIAL) ARISING FROM ITS USE.
# 3. THIS SCRIPT DOES NOT CONSTITUTE OFFICIAL BILLING ADVICE. ALWAYS REFER TO 
#    YOUR OFFICIAL AWS INVOICE FOR EXACT CHARGES.
# ==============================================================================

import time
import datetime
import sys

# --- Imports ---
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError as e:
    print("CRITICAL ERROR: Missing required AWS library.")
    print(f"Details: {e}")
    print("\nPlease run the following command to install it:")
    print("pip install boto3")
    sys.exit(1)

# --- Configuration ---
CROSS_ACCOUNT_ROLE_NAME = "OrganizationAccountAccessRole" # Change if you use a custom cross-account role
DAYS = 30
SHOW_SINKS = True # Set to False if you want to hide the Subscription Filter output to keep the console clean

# Google SecOps Supported AWS Log Types (24 total) and their common CloudWatch naming keywords
SECOPS_MAPPINGS = {
    "AWS CloudTrail logs": ["cloudtrail"],
    "AWS EC2 Hosts logs": ["ec2-host", "ec2_host"], 
    "AWS EC2 Instance logs": ["ec2-instance", "ec2_instance", "syslog", "messages"],
    "AWS API Gateway access logs": ["apigateway", "api-gateway"],
    "AWS Aurora logs": ["aurora"],
    "AWS CloudWatch logs": ["cloudwatch"],
    "AWS Config logs": ["config"],
    "AWS Control Tower logs": ["controltower", "control-tower"],
    "AWS Elastic Load Balancing logs": ["elasticloadbalancing", "elb", "alb", "nlb"],
    "AWS Elastic MapReduce logs": ["emr", "elasticmapreduce"],
    "AWS GuardDuty logs": ["guardduty"],
    "AWS IAM logs": ["iam"],
    "AWS Key Management Service logs": ["kms"],
    "AWS Macie logs": ["macie"],
    "AWS Network Firewall logs": ["network-firewall", "networkfirewall"],
    "AWS RDS logs": ["rds"],
    "AWS Route 53 logs": ["route53", "route-53"],
    "AWS S3 server access logs": ["s3-access", "s3_access", "s3-server-access"],
    "AWS Security Hub logs": ["securityhub", "security-hub"],
    "AWS Session Manager logs": ["session-manager", "sessionmanager", "ssm"],
    "AWS VPC flow logs": ["vpc-flow", "vpc_flow", "flowlog", "flow-log"],
    "AWS VPC Transit Gateway flow logs": ["transitgateway", "tgw"],
    "AWS VPN logs": ["vpn"],
    "AWS WAF logs": ["waf"]
}

def get_accounts_in_org():
    """Lists all ACTIVE accounts within the AWS Organization."""
    print("Searching for active accounts in AWS Organization...")
    try:
        client = boto3.client('organizations')
        accounts = []
        paginator = client.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            for account in page['Accounts']:
                if account['Status'] == 'ACTIVE':
                    accounts.append(account['Id'])
                    
        print(f"Found {len(accounts)} active accounts.")
        return accounts
    except ClientError as e:
        print(f"\n[!] Error listing accounts: {e}")
        print("Tip: Ensure you are running this in the Management/Delegated Admin account.")
        sys.exit(1)

def assume_role(account_id):
    """Assumes a cross-account role to access sub-accounts."""
    sts_client = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}"
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="SecOpsLogVolumeAudit"
        )
        return boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
    except ClientError:
        return None

def process_account_logs(session, account_id):
    """
    Iterates through regions, calculates Log Group ingestion, categorizes by SecOps 
    supported parsers, and fetches Subscription Filters (Sinks).
    """
    ec2_client = session.client('ec2', region_name='us-east-1')
    try:
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    except ClientError:
        print("      [!] Could not list regions. Skipping account.")
        return 0, {}

    total_bytes = 0
    account_categories = {key: 0 for key in SECOPS_MAPPINGS.keys()}
    account_categories["Other / Uncategorized"] = 0
    
    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(days=DAYS)

    for region in regions:
        logs_client = session.client('logs', region_name=region)
        cw_client = session.client('cloudwatch', region_name=region)
        
        try:
            paginator = logs_client.get_paginator('describe_log_groups')
            log_groups = []
            
            for page in paginator.paginate():
                log_groups.extend(page['logGroups'])
                
            if not log_groups:
                continue

            for lg in log_groups:
                lg_name = lg['logGroupName']
                lower_name = lg_name.lower()
                
                # 1. Get Volume for the Log Group
                metrics = cw_client.get_metric_statistics(
                    Namespace='AWS/Logs',
                    MetricName='IncomingBytes',
                    Dimensions=[{'Name': 'LogGroupName', 'Value': lg_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=DAYS * 24 * 60 * 60,
                    Statistics=['Sum']
                )
                
                if metrics['Datapoints']:
                    lg_bytes = metrics['Datapoints'][0]['Sum']
                    total_bytes += lg_bytes
                    
                    # 2. Categorize based on SecOps supported lists
                    matched = False
                    for category, keywords in SECOPS_MAPPINGS.items():
                        if any(kw in lower_name for kw in keywords):
                            account_categories[category] += lg_bytes
                            matched = True
                            break
                    
                    if not matched:
                        account_categories["Other / Uncategorized"] += lg_bytes

                # 3. Get Subscription Filters (Log Sinks)
                if SHOW_SINKS:
                    filters = logs_client.describe_subscription_filters(logGroupName=lg_name).get('subscriptionFilters', [])
                    if filters:
                        for sub in filters:
                            print(f"      > Sink Name:        {sub.get('filterName')}")
                            print(f"        Region:           {region}")
                            print(f"        Log Group:        {lg_name}")
                            print(f"        Destination ARN:  {sub.get('destinationArn')}")
                            
                            inc_filter = sub.get('filterPattern') if sub.get('filterPattern') else "(All Logs)"
                            if len(inc_filter) > 80: inc_filter = inc_filter[:77] + "..."
                            print(f"        Filter Pattern:   {inc_filter}\n")

        except ClientError:
            pass # Skip restricted/disabled regions
            
    return total_bytes, account_categories

# --- Main Execution ---
if __name__ == "__main__":
    # --- PRINT DISCLAIMER ---
    print("\n" + "#" * 80)
    print(" DISCLAIMER - PLEASE READ CAREFULLY")
    print("#" * 80)
    print(" This script is provided for informational purposes only and is NOT an official")
    print(" AWS product. It estimates log ingestion and lists subscription configurations.")
    print("")
    print(" BY PROCEEDING, YOU ACKNOWLEDGE THAT:")
    print(" 1. YOU USE THIS SCRIPT AT YOUR OWN RISK.")
    print(" 2. THE AUTHOR(S) ARE NOT LIABLE FOR ANY ERRORS, OMISSIONS, OR DAMAGES.")
    print(" 3. THIS DOES NOT REPLACE YOUR OFFICIAL AWS INVOICE.")
    print("#" * 80 + "\n")

    try:
        agreement = input(">> Do you agree to these terms? (y/n): ").strip().lower()
    except KeyboardInterrupt:
        sys.exit(0)

    if agreement != 'y':
        print("\n[!] You did not agree to the terms. Exiting script.")
        sys.exit(0)

    print("\n" + "=" * 80)
    print("   AWS CloudWatch Logs: Google SecOps Ingestion Volume Calculator (30 Days)")
    print("=" * 80 + "\n")

    accounts = get_accounts_in_org()
    if not accounts:
        sys.exit(1)

    grand_total_bytes = 0
    master_categories = {key: 0 for key in SECOPS_MAPPINGS.keys()}
    master_categories["Other / Uncategorized"] = 0
    
    accounts_scanned = 0
    accounts_skipped = 0
    
    print("\nProcessing accounts... (This may take several minutes)\n")

    default_session = boto3.Session()
    default_account_id = default_session.client('sts').get_caller_identity().get('Account')

    for acc_id in accounts:
        print("-" * 80)
        print(f"ACCOUNT: {acc_id}")
        
        session = default_session if acc_id == default_account_id else assume_role(acc_id)

        if session:
            accounts_scanned += 1
            total_bytes, acc_cats = process_account_logs(session, acc_id)
            
            grand_total_bytes += total_bytes
            
            for cat, bytes_val in acc_cats.items():
                master_categories[cat] += bytes_val

            print(f"  Total Ingest (Last 30 Days):  {total_bytes / (1024**3):,.4f} GB")
        else:
            accounts_skipped += 1
            print(f"  [!] Failed to assume cross-account role '{CROSS_ACCOUNT_ROLE_NAME}'. (SKIPPED)")

    # --- Final Calculations ---
    total_gb_30d = grand_total_bytes / (1024**3)
    total_tb_30d = grand_total_bytes / (1024**4)
    
    print("\n" + "=" * 80)
    print("ORGANIZATION TOTALS (LAST 30 DAYS)")
    print("=" * 80)
    print(f"Accounts Scanned:        {accounts_scanned} (Skipped: {accounts_skipped})")
    print(f"TOTAL VOLUME:            {total_tb_30d:,.4f} TB ({total_gb_30d:,.2f} GB)\n")
    
    print("SECOPS SUPPORTED LOG CATEGORY BREAKDOWN:")
    print("-" * 80)
    
    uncategorized_val = master_categories.pop("Other / Uncategorized")
    sorted_cats = sorted(master_categories.items(), key=lambda item: item[1], reverse=True)
    
    for cat, b_val in sorted_cats:
        cat_gb = b_val / (1024**3)
        percentage = (b_val / grand_total_bytes) * 100 if grand_total_bytes > 0 else 0
        print(f"  ├─ {cat:<35}: {cat_gb:>10,.4f} GB  ({percentage:>5.1f}%)")

    uncat_gb = uncategorized_val / (1024**3)
    uncat_percentage = (uncategorized_val / grand_total_bytes) * 100 if grand_total_bytes > 0 else 0
    print(f"  └─ {'Other / Uncategorized':<35}: {uncat_gb:>10,.4f} GB  ({uncat_percentage:>5.1f}%)")
            
    print("=" * 80)