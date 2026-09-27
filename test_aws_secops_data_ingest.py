import io
import unittest
from unittest.mock import MagicMock, patch
import importlib

from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError

import sys
# Make sure we import the module under test
import importlib.util
spec = importlib.util.spec_from_file_location("aws_secops_ingest", "aws-secops-data-ingest.py")
aws_secops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aws_secops)


class TestAwsSecopsDataIngest(unittest.TestCase):

    def test_get_accounts_in_org_success(self):
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'Accounts': [
                    {'Id': '111111111111', 'Status': 'ACTIVE'},
                    {'Id': '222222222222', 'Status': 'SUSPENDED'},
                    {'Id': '333333333333', 'Status': 'ACTIVE'},
                ]
            }
        ]

        accounts = aws_secops.get_accounts_in_org(mock_session)
        self.assertEqual(accounts, ['111111111111', '333333333333'])

    def test_get_accounts_in_org_client_error(self):
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        
        error_response = {'Error': {'Code': 'AWSOrganizationsNotInUseException', 'Message': 'Not in org'}}
        mock_paginator.paginate.side_effect = ClientError(error_response, 'ListAccounts')

        with self.assertRaises(SystemExit) as cm:
            aws_secops.get_accounts_in_org(mock_session)
        self.assertEqual(cm.exception.code, 1)

    def test_get_accounts_in_org_nocredentials_error(self):
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client
        mock_client.get_paginator.side_effect = NoCredentialsError()

        with self.assertRaises(SystemExit) as cm:
            aws_secops.get_accounts_in_org(mock_session)
        self.assertEqual(cm.exception.code, 1)

    def test_assume_role_success(self):
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_session.client.return_value = mock_sts

        mock_sts.assume_role.return_value = {
            'Credentials': {
                'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
                'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                'SessionToken': 'TOKEN123'
            }
        }

        with patch('boto3.Session') as mock_boto_session:
            assumed = aws_secops.assume_role('123456789012', base_session=mock_session)
            self.assertIsNotNone(assumed)
            mock_sts.assume_role.assert_called_once_with(
                RoleArn="arn:aws:iam::123456789012:role/OrganizationAccountAccessRole",
                RoleSessionName="SecOpsLogVolumeAudit"
            )

    def test_assume_role_failure(self):
        mock_session = MagicMock()
        mock_sts = MagicMock()
        mock_session.client.return_value = mock_sts
        error_response = {'Error': {'Code': 'AccessDenied', 'Message': 'Cannot assume role'}}
        mock_sts.assume_role.side_effect = ClientError(error_response, 'AssumeRole')

        assumed = aws_secops.assume_role('123456789012', base_session=mock_session)
        self.assertIsNone(assumed)

    def test_process_account_logs_summation_and_categorization(self):
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_logs = MagicMock()
        mock_cw = MagicMock()

        def client_side_effect(service, region_name=None):
            if service == 'ec2':
                return mock_ec2
            elif service == 'logs':
                return mock_logs
            elif service == 'cloudwatch':
                return mock_cw
            return MagicMock()

        mock_session.client.side_effect = client_side_effect

        # EC2 Describe Regions
        mock_ec2.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-1'}]
        }

        # CloudWatch Logs Describe Log Groups
        mock_paginator = MagicMock()
        mock_logs.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'logGroups': [
                    {'logGroupName': '/aws/cloudtrail/management-events'},
                    {'logGroupName': '/aws/vpc/flow-logs'},
                    {'logGroupName': '/custom/application-debug'}
                ]
            }
        ]

        # CloudWatch Metrics: Multiple datapoints to test summation fix
        def cw_get_metric_stats(Namespace, MetricName, Dimensions, StartTime, EndTime, Period, Statistics):
            lg = Dimensions[0]['Value']
            if 'cloudtrail' in lg:
                # 3 daily datapoints: 1000, 2000, 3000 -> Sum must be 6000
                return {'Datapoints': [{'Sum': 1000.0}, {'Sum': 2000.0}, {'Sum': 3000.0}]}
            elif 'vpc' in lg:
                # 2 daily datapoints: 4000, 6000 -> Sum must be 10000
                return {'Datapoints': [{'Sum': 4000.0}, {'Sum': 6000.0}]}
            elif 'custom' in lg:
                return {'Datapoints': [{'Sum': 500.0}]}
            return {'Datapoints': []}

        mock_cw.get_metric_statistics.side_effect = cw_get_metric_stats

        # CloudWatch Subscription Filters
        def describe_subs(logGroupName):
            if 'cloudtrail' in logGroupName:
                return {
                    'subscriptionFilters': [
                        {
                            'filterName': 'CloudTrailToSecOps',
                            'destinationArn': 'arn:aws:kinesis:us-east-1:123456789012:stream/secops',
                            'filterPattern': '[version, account, ...]'
                        }
                    ]
                }
            return {'subscriptionFilters': []}

        mock_logs.describe_subscription_filters.side_effect = describe_subs

        total_bytes, categories, metric_errs, sinks = aws_secops.process_account_logs(
            mock_session, '123456789012', days=30, show_sinks=True
        )

        self.assertEqual(metric_errs, 0)
        # Total bytes: 6000 + 10000 + 500 = 16500
        self.assertEqual(total_bytes, 16500.0)
        self.assertEqual(categories["AWS CloudTrail logs"], 6000.0)
        self.assertEqual(categories["AWS VPC flow logs"], 10000.0)
        self.assertEqual(categories["Other / Uncategorized"], 500.0)
        self.assertEqual(len(sinks), 1)
        self.assertEqual(sinks[0]['name'], 'CloudTrailToSecOps')
        self.assertEqual(sinks[0]['region'], 'us-east-1')

    def test_process_account_logs_metric_error_resilience(self):
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_logs = MagicMock()
        mock_cw = MagicMock()

        mock_session.client.side_effect = lambda s, region_name=None: {
            'ec2': mock_ec2,
            'logs': mock_logs,
            'cloudwatch': mock_cw
        }[s]

        mock_ec2.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-1'}]
        }

        mock_paginator = MagicMock()
        mock_logs.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'logGroups': [
                    {'logGroupName': '/aws/waf/bad-permissions'},
                    {'logGroupName': '/aws/waf/good-group'}
                ]
            }
        ]

        # First log group fails with ClientError, second succeeds
        error_response = {'Error': {'Code': 'AccessDenied', 'Message': 'Forbidden'}}
        mock_cw.get_metric_statistics.side_effect = [
            ClientError(error_response, 'GetMetricStatistics'),
            {'Datapoints': [{'Sum': 2500.0}]}
        ]
        mock_logs.describe_subscription_filters.return_value = {'subscriptionFilters': []}

        total_bytes, categories, metric_errs, sinks = aws_secops.process_account_logs(
            mock_session, '123456789012', days=30, show_sinks=True
        )

        # Ensure metric_errs counter is incremented, and good-group was NOT dropped!
        self.assertEqual(metric_errs, 1)
        self.assertEqual(total_bytes, 2500.0)
        self.assertEqual(categories["AWS WAF logs"], 2500.0)

    def test_process_account_logs_region_failure(self):
        mock_session = MagicMock()
        mock_ec2 = MagicMock()
        mock_session.client.return_value = mock_ec2
        error_response = {'Error': {'Code': 'AuthFailure', 'Message': 'Cannot auth'}}
        mock_ec2.describe_regions.side_effect = ClientError(error_response, 'DescribeRegions')

        total_bytes, categories, metric_errs, sinks = aws_secops.process_account_logs(
            mock_session, '123456789012'
        )

        self.assertIsNone(total_bytes)
        self.assertEqual(categories, {})
        self.assertEqual(metric_errs, 0)
        self.assertEqual(sinks, [])

    def test_organization_totals_and_formatting(self):
        # Verify decimal GB and TB conversions
        grand_total_bytes = 1_500_000_000_000  # 1.5 TB decimal
        total_gb = grand_total_bytes / (1000**3)
        total_tb = grand_total_bytes / (1000**4)

        self.assertEqual(total_gb, 1500.0)
        self.assertEqual(total_tb, 1.5)

        # Verify category sorting and percentage calculation
        categories = {k: 0 for k in aws_secops.SECOPS_MAPPINGS}
        categories["Other / Uncategorized"] = 150_000_000_000 # 10%
        categories["AWS CloudTrail logs"] = 900_000_000_000    # 60%
        categories["AWS VPC flow logs"] = 450_000_000_000      # 30%

        uncategorized_val = categories.get("Other / Uncategorized", 0)
        categorized_items = [
            (k, v) for k, v in categories.items() if k != "Other / Uncategorized"
        ]
        sorted_cats = sorted(categorized_items, key=lambda item: item[1], reverse=True)

        self.assertEqual(sorted_cats[0][0], "AWS CloudTrail logs")
        self.assertEqual(sorted_cats[0][1], 900_000_000_000)
        self.assertEqual(sorted_cats[1][0], "AWS VPC flow logs")
        self.assertEqual(sorted_cats[1][1], 450_000_000_000)

        cloudtrail_pct = (sorted_cats[0][1] / grand_total_bytes) * 100
        self.assertAlmostEqual(cloudtrail_pct, 60.0, places=1)

        uncat_pct = (uncategorized_val / grand_total_bytes) * 100
        self.assertAlmostEqual(uncat_pct, 10.0, places=1)


if __name__ == '__main__':
    unittest.main()

