# -*- coding: utf-8 -*-

"""
Report AWS EC2 instances across the entire Organization.

"""

from helpers            import LOGGER, SESSION, MANDATORY_TAGS   # Global vars
from helpers.looper     import loop_function, make_list_acc_region
from helpers.csv_files  import csv_writer
from helpers.boto3_func import *


def query_by_account(aws: dict) -> list:
    """Trigger a query at each active region by AWS account in parallel."""
    regions = get_regions(SESSION)
    acc_region_list = make_list_acc_region(regions, aws)

    return loop_function(acc_region_list, query_by_region, False)


def query_by_region(aws: dict) -> list:
    """Run query at each AWS accounts."""
    csv_rows = list()

    # Get boto3 EC2 client per region
    ec2 = get_boto3_client(SESSION, aws['AccountId'], 'ec2', region=aws['Region'])
    # Filter to Grab all EC2 instances in the AWS account and region
    ec2_filter = [
        {
            'Name': 'instance-state-name',
            'Values': [
                'pending',
                'running',
                'stopping',
                'stopped'
            ]
        }
    ]

    # Loop through a list of EC2 instances by AWS account in a single region
    for ec2s in list(paginate(ec2, 'describe_instances', Filters=ec2_filter)):
        # Build the report by AWS account
        for r in ec2s['Instances']:
            # Write CSV column row
            csv_row = [
                aws['AccountId'],
                aws['AccountAlias'],
                aws['Region'],
                r['InstanceId'],
                r['ImageId'],
                r['State']['Name'],
                r['InstanceType'],
                try_get_value(r, 'KeyName'),
                r['LaunchTime'],
                get_days_since(r['LaunchTime']),
                try_get_value(r, 'PrivateIpAddress'),
                try_get_value(r, 'PublicIpAddress'),
                try_get_value(r, 'VpcId'),
                try_get_value(r, 'SubnetId'),
                r['Architecture'],
                get_ec2_platform(r, 'Platform'),
                get_instance_profile(r, 'IamInstanceProfile')
            ]

            # Add tagging column values to each row
            resource_tags = get_tags(r, MANDATORY_TAGS.copy())
            csv_row += get_tag_values(resource_tags)

            # Add new row to CSV file
            csv_rows.append(csv_row)

    return csv_rows


def query_output(result: list):
    """Generate a CSV file que the query results."""
    # Headers for the CSV file
    csv_headers = [
        'AWS Account ID',
        'AWS Account Alias',
        'AWS Region',
        'Instance ID',
        'State',
        'Image ID',
        'Instance type',
        'Key name',
        'Launch Time',
        'Days old',
        'Private IP address',
        'Public IP address',
        'VPC ID',
        'Subnet ID',
        'Architecture',
        'Platform',
        'IAM Instance Profile ARN'
    ]

    # Add tagging column names to the headers
    csv_headers += get_tag_keys(MANDATORY_TAGS)

    # Generate report query as CSV file
    file_path = 'query_results/ec2_instances.csv'
    csv_writer(file_path, result, csv_headers)


if __name__ == '__main__':
    LOGGER.info('Starting query...')

    # Loop through all accounts and run a boto3 query in parallel
    result = loop_function(
        get_active_accounts(SESSION),   # Active AWS accounts in the Org
        query_by_account,               # Query to run per AWS account
        True                            # Flag to display result summary
    )

    # Send the results to a csv file
    query_output(result)
