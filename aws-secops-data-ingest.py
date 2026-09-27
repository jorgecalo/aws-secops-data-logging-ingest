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

import datetime
import sys

# --- Imports ---
try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
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

def get_accounts_in_org(session=None):
    """Lists all ACTIVE accounts within the AWS Organization."""
    print("Searching for active accounts in AWS Organization...")
    try:
        org_client = (session or boto3.Session()).client('organizations')
        accounts = []
        paginator = org_client.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            for account in page.get('Accounts', []):
                if account.get('Status') == 'ACTIVE':
                    accounts.append(account['Id'])
                    
        print(f"Found {len(accounts)} active accounts.")
        return accounts
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        print(f"\n[!] Error listing accounts: {e}")
        if error_code == 'AWSOrganizationsNotInUseException':
            print("Tip: This account is not part of an AWS Organization.")
        else:
            print("Tip: Ensure you are running this in the Management/Delegated Admin account.")
        sys.exit(1)
    except BotoCoreError as e:
        print(f"\n[!] AWS connection or credential error: {e}")
        print("Tip: Check your AWS credentials and configuration (e.g. run 'aws configure').")
        sys.exit(1)

def assume_role(account_id, role_name=CROSS_ACCOUNT_ROLE_NAME, base_session=None):
    """Assumes a cross-account role to access sub-accounts."""
    sts_client = (base_session or boto3.Session()).client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
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
    except (ClientError, BotoCoreError):
        return None

def process_account_logs(session, account_id, days=DAYS, show_sinks=SHOW_SINKS):
    """
    Iterates through enabled regions, calculates Log Group ingestion, categorizes by SecOps 
    supported parsers, and fetches Subscription Filters (Sinks).
    Returns (total_bytes, account_categories, metric_errors, sinks).
    If regions cannot be listed, returns (None, {}, 0, []).
    """
    ec2_client = session.client('ec2', region_name='us-east-1')
    try:
        regions_response = ec2_client.describe_regions(
            Filters=[{'Name': 'opt-in-status', 'Values': ['opt-in-not-required', 'opted-in']}]
        )
        regions = [region['RegionName'] for region in regions_response.get('Regions', [])]
    except (ClientError, BotoCoreError):
        try:
            regions = [region['RegionName'] for region in ec2_client.describe_regions().get('Regions', [])]
        except (ClientError, BotoCoreError):
            print("  [!] Could not list regions. Skipping account.")
            return None, {}, 0, []

    total_bytes = 0
    account_categories = {key: 0 for key in SECOPS_MAPPINGS.keys()}
    account_categories["Other / Uncategorized"] = 0
    metric_errors = 0
    account_sinks = []
    
    end_time = datetime.datetime.now(datetime.timezone.utc)
    start_time = end_time - datetime.timedelta(days=days)

    for region in regions:
        logs_client = session.client('logs', region_name=region)
        cw_client = session.client('cloudwatch', region_name=region)
        
        try:
            paginator = logs_client.get_paginator('describe_log_groups')
            log_groups = []
            for page in paginator.paginate():
                log_groups.extend(page.get('logGroups', []))
        except (ClientError, BotoCoreError):
            # Skip restricted/disabled regions or permission-denied regions
            continue

        if not log_groups:
            continue

        for lg in log_groups:
            lg_name = lg['logGroupName']
            lower_name = lg_name.lower()
            
            # 1. Get Volume for the Log Group
            # Use 86400 (1 day) period so all daily datapoints are returned and aggregated,
            # avoiding epoch boundary truncation bugs when using 30-day periods.
            try:
                metrics = cw_client.get_metric_statistics(
                    Namespace='AWS/Logs',
                    MetricName='IncomingBytes',
                    Dimensions=[{'Name': 'LogGroupName', 'Value': lg_name}],
                    StartTime=start_time,
                    EndTime=end_time,
                    Period=86400,
                    Statistics=['Sum']
                )
                datapoints = metrics.get('Datapoints', [])
                if datapoints:
                    lg_bytes = sum(dp.get('Sum', 0) for dp in datapoints)
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

            except (ClientError, BotoCoreError):
                metric_errors += 1

            # 3. Get Subscription Filters (Log Sinks)
            if show_sinks:
                try:
                    filters = logs_client.describe_subscription_filters(
                        logGroupName=lg_name
                    ).get('subscriptionFilters', [])
                    for sub in filters:
                        account_sinks.append({
                            'name': sub.get('filterName'),
                            'region': region,
                            'log_group': lg_name,
                            'destination_arn': sub.get('destinationArn'),
                            'filter_pattern': sub.get('filterPattern') or "(All Logs)"
                        })
                except (ClientError, BotoCoreError):
                    pass
            
    return total_bytes, account_categories, metric_errors, account_sinks

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
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)

    if agreement != 'y':
        print("\n[!] You did not agree to the terms. Exiting script.")
        sys.exit(0)

    print("\n" + "=" * 80)
    print("   AWS CloudWatch Logs: Google SecOps Ingestion Volume Calculator (30 Days)")
    print("=" * 80 + "\n")

    default_session = boto3.Session()
    try:
        default_account_id = default_session.client('sts').get_caller_identity().get('Account')
    except (ClientError, BotoCoreError) as e:
        print(f"[!] Error verifying caller identity: {e}")
        print("Tip: Check your AWS credentials and configuration (e.g. run 'aws configure').")
        sys.exit(1)

    accounts = get_accounts_in_org(default_session)
    if not accounts:
        print("[!] No active accounts found.")
        sys.exit(1)

    grand_total_bytes = 0
    master_categories = {key: 0 for key in SECOPS_MAPPINGS.keys()}
    master_categories["Other / Uncategorized"] = 0
    
    accounts_scanned = 0
    accounts_skipped = 0
    grand_metric_errors = 0
    
    print("\nProcessing accounts... (This may take several minutes)\n")

    for acc_id in accounts:
        print("-" * 80)
        print(f"ACCOUNT: {acc_id}")
        print("-" * 80)
        
        session = default_session if acc_id == default_account_id else assume_role(acc_id, base_session=default_session)

        if session:
            total_bytes, acc_cats, metric_errs, sinks = process_account_logs(
                session, acc_id, days=DAYS, show_sinks=SHOW_SINKS
            )
            
            if total_bytes is None:
                accounts_skipped += 1
                continue

            accounts_scanned += 1
            grand_metric_errors += metric_errs
            grand_total_bytes += total_bytes
            
            for cat, bytes_val in acc_cats.items():
                master_categories[cat] += bytes_val

            # Convert bytes to decimal GB (10^9 bytes) for Google SecOps platform alignment
            gb_total = total_bytes / (1000**3)

            print(f"  VOLUME (Last 30 Days):")
            print(f"  Total Ingest:  {gb_total:,.4f} GB")
            print("")

            if SHOW_SINKS:
                print(f"  SUBSCRIPTION FILTERS (LOG SINKS):")
                if sinks:
                    for sub in sinks:
                        inc_filter = sub['filter_pattern']
                        if len(inc_filter) > 80:
                            inc_filter = inc_filter[:77] + "..."
                        print(f"     > Sink Name:        {sub['name']}")
                        print(f"       Region:           {sub['region']}")
                        print(f"       Log Group:        {sub['log_group']}")
                        print(f"       Destination ARN:  {sub['destination_arn']}")
                        print(f"       Filter Pattern:   {inc_filter}\n")
                else:
                    print("     [i] No Subscription Filters configured.\n")
        else:
            accounts_skipped += 1
            print(f"  [!] Failed to assume cross-account role '{CROSS_ACCOUNT_ROLE_NAME}'. (SKIPPED)")

    # --- Final Calculations ---
    # Convert bytes to decimal GB (10^9 bytes) and TB (10^12 bytes) matching Google SecOps
    total_gb_30d = grand_total_bytes / (1000**3)
    total_tb_30d = grand_total_bytes / (1000**4)
    
    print("=" * 80)
    print("ORGANIZATION TOTALS")
    print("=" * 80)
    print(f"Accounts Found:          {len(accounts)}")
    print(f"Accounts Scanned:        {accounts_scanned}")
    print(f"Accounts Skipped:        {accounts_skipped}")
    if grand_metric_errors:
        print(f"Metric Read Errors:      {grand_metric_errors} (counted as 0 bytes)")
    print("-" * 40)
    print(f"TOTAL VOLUME (30 Days):  {total_tb_30d:,.4f} TB")
    print(f"                         ({total_gb_30d:,.2f} GB)\n")
    
    print("SECOPS SUPPORTED LOG CATEGORY BREAKDOWN:")
    print("-" * 80)
    
    uncategorized_val = master_categories.get("Other / Uncategorized", 0)
    categorized_items = [
        (k, v) for k, v in master_categories.items() if k != "Other / Uncategorized"
    ]
    sorted_cats = sorted(categorized_items, key=lambda item: item[1], reverse=True)
    
    for cat, b_val in sorted_cats:
        cat_gb = b_val / (1000**3)
        percentage = (b_val / grand_total_bytes) * 100 if grand_total_bytes > 0 else 0
        print(f"  ├─ {cat:<35}: {cat_gb:>10,.4f} GB  ({percentage:>5.1f}%)")

    uncat_gb = uncategorized_val / (1000**3)
    uncat_percentage = (uncategorized_val / grand_total_bytes) * 100 if grand_total_bytes > 0 else 0
    print(f"  └─ {'Other / Uncategorized':<35}: {uncat_gb:>10,.4f} GB  ({uncat_percentage:>5.1f}%)")
            
    print("=" * 80)