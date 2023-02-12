# -*- coding: utf-8 -*-
"""General useful functions."""

import logging

from botocore.exceptions import ClientError
from datetime import datetime
from dateutil.parser import parse

from classes.assume_role import StsObject

from helpers import SERVICE_ACCOUNT_ID, SERVICE_ROLE_NAME

LOGGER = logging.getLogger(__name__)


def get_boto3_client(session: object, account_id: str, service: str, region='ap-southeast-2') -> object:
    """Get boto3 client service."""
    # Service AWS account and service role
    service_account = SERVICE_ACCOUNT_ID
    service_role_name = SERVICE_ROLE_NAME

    # root organization account doesn't have the IAM Role used in the child accounts
    if account_id != service_account:
        # Assume service role on target AWS account
        sts_obj = StsObject(
            session,
            account_id,
            service_role_name
        )
        # Set boto3 client using STS credentials
        service = sts_obj.get_client(
            service,
            region
        )
    # for the service account you no need to assume another role instead use your own
    else:
        service = session.client(service, region)

    return service


def get_boto3_resource(session: object, account_id: str, service: str, region='ap-southeast-2') -> object:
    """Get boto3 client service."""
    # Service AWS account and service role
    service_account = SERVICE_ACCOUNT_ID
    service_role_name = SERVICE_ROLE_NAME

    # root organization account doesn't have the IAM Role used in the child accounts
    if account_id != service_account:
        # Assume service role on target AWS account
        sts_obj = StsObject(
            session,
            account_id,
            service_role_name
        )
        # Set boto3 resource using STS credentials
        resource = sts_obj.get_resource(
            service,
            region
        )
    # for the service account you no need to assume another role instead use your own
    else:
        resource = session.resource(service, region)

    return resource


def get_active_accounts(session: object) -> list:
    """Get the list of active AWS accounts in the Organization."""
    aws_accounts_id_alias = list()
    if (org := session.client('organizations')):
        aws_accounts_raw = list(paginate(org, 'list_accounts'))
        for account in aws_accounts_raw:
            if account['Status'] == 'ACTIVE':
                aws_accounts_id_alias.append(
                    {
                        'AccountId': account['Id'],
                        'AccountAlias': account['Name']
                    }
                )

    return aws_accounts_id_alias


def get_regions(session: object) -> list:
    """Gets Regions Enabled for Account."""
    regions = list()
    if (ec2 := session.client('ec2')):
        try:
            response = ec2.describe_regions(
                AllRegions=False
                )

            for region in response['Regions']:
                regions.append(region['RegionName'])

        except ClientError as e:
            message = 'Error getting list of regions: {}'.format(e)
            LOGGER.error(message)

    return regions


def paginate(client: object, method: str, **kwargs) -> list:
    """Paginate boto3 client methods."""
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs).result_key_iters():
        for result in page:
            yield result


def get_value_if_any(dictionary: dict, key: str) -> str:
    """Look for a dictionary key and return its value if exist."""
    if key in dictionary.keys():
        value = dictionary[key]
    else:
        value = 'NoValue'

    return value


def try_get_value(dictionary: dict, key: str) -> str:
    """Get value from dictionary if the key exist."""
    try:
        value = dictionary[key]
    except: # pylint: disable=broad-except
        value = 'NoValue'

    return value


def get_ec2_platform(dictionary: dict, key: str) -> str:
    """Check if ec2 platform is Windows or Linux."""
    try:
        platform = dictionary[key]
    except: # pylint: disable=broad-except
        platform = 'Linux'

    return platform

def get_instance_profile(dictionary: dict, key: str) -> str:
    """Check if ec2 have instance profile and return the ARN if any."""
    try:
        instance_profile = dictionary[key]
        instance_profile_arn = instance_profile['Arn']

    except: # pylint: disable=broad-except
        instance_profile_arn = 'NoValue'

    return instance_profile_arn

def _curated_str(string: str) -> str:
    """Remove CSV file conflictive characters from string."""
    return string.replace('\"', '').replace('\'', '').replace(',', ';')


def get_tags(aws_response: dict, tags_of_interest) -> list:
    """Get mandatory TAGs if those are set."""
    try:
        tags = get_critical_tags(aws_response['Tags'], tags_of_interest)
    except: # pylint: disable=broad-except
        tags = tags_of_interest

    return tags


def get_critical_tags(tags_list: list, tags_of_interest: dict) -> dict:
    """Fetch critical TAGs and curate static values."""
    if tags_list:
        for tags in tags_list:
            if tags['Key'] in tags_of_interest.keys():
                # Remove un-wanted characteres
                tags_of_interest[tags['Key']] = _curated_str(tags['Value'])

    return tags_of_interest



def get_critical_tags_raw(tags_list: list, tags_of_interest: dict) -> dict:
    """Fetch critical TAG values in raw format."""
    for tags in tags_list:
        if tags['Key'] in tags_of_interest.keys():
            tags_of_interest[tags['Key']] = tags['Value']

    return tags_of_interest


def get_tag_value_by_key(tags: list, key_value: str) -> str:
    """Get a Tag value searching by the Key."""
    key_pair = next(
        (tag for tag in tags if tag['Key'] == key_value),
        None
    )
    if key_pair:
        return _curated_str(key_pair['Value'])
    else:
        return 'NoValue'


def get_tag_value_by_key_raw(tags: list, key_value: str) -> str:
    """Get a Tag value searching by the Key."""
    key_pair = next(
        (tag for tag in tags if tag['Key'] == key_value),
        None
    )
    if key_pair:
        return key_pair['Value']
    else:
        return 'NoValue'


def get_tag_values(tags: dict) -> list:
    """Get tag values."""
    tag_values_list = list()
    count_missing_tags = 0
    for t in tags.keys():
        tag_values_list.append(tags[t])
        if tags[t] == 'NoValue':
            count_missing_tags += 1

    tag_values_list.append(count_missing_tags)

    return tag_values_list


def get_tag_keys(tags: dict) -> list:
    """Get tag key names."""
    tag_keys_list = list()
    for t in tags.keys():
        tag_keys_list.append(t)

    tag_keys_list.append('Count of Missing TAGs')

    return tag_keys_list


def format_date(date_field: datetime) -> str:
    """Format date field into string like DD/MM/YYYY HH:MM."""
    return datetime.strptime(
                str(date_field),
                '%Y-%m-%d %H:%M:%S%z'
            ).strftime('%-d/%m/%y %-H:%M')


def get_days_since(date: str) -> int:
    """Count days since specific date to today."""
    if isinstance(date, str):
        get_date_obj = parse(date)
        date_obj = get_date_obj.replace(tzinfo=None)
    else:
        date_obj = date.replace(tzinfo=None)

    diff = datetime.now() - date_obj

    return diff.days
