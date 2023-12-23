# -*- coding: utf-8 -*-
"""General useful functions to support boto3 api calls."""

import ast
from sys import exit as leave
from logging import getLogger
from datetime import datetime
from dateutil.parser import parse  # pylint: disable=import-error
from botocore.exceptions import ClientError, SSOTokenLoadError, \
                                UnauthorizedSSOTokenError  # pylint: disable=import-error

from classes.looper import Looper
from classes.assume_role import StsObject
from classes.arn_handler import ArnHandler
from classes.tag import Tag
from helpers import config

LOGGER = getLogger(__name__)


def validate_sts_token():
    """Check if the user running the query is authenticated."""
    sts = b3_client(config.SERVICE_ACCOUNT_ID, 'sts')

    try:
        caller = sts.get_caller_identity()
    except UnauthorizedSSOTokenError as erro:
        abort_script(erro)
    except SSOTokenLoadError as erro:
        abort_script(erro)
    except ClientError as erro:
        abort_script(erro)

    return caller


def b3_client(account_id: str, service: str, region=config.REGION) -> object:
    """Get boto3 client service."""
    # root org account doesn't have the IAM Role used in the child accounts
    if account_id != config.SERVICE_ACCOUNT_ID:
        # Assume service role on target AWS account
        sts_obj = StsObject(
            config.SESSION,
            account_id,
            config.SERVICE_ROLE_NAME
        )
        # Set boto3 client using STS credentials
        client = sts_obj.get_client(service, region)
    else:
        # The service account is already authenticated with user's IAM role
        client = config.SESSION.client(service, region)

    return client


def b3_resource(account_id: str, service: str, region='ap-southeast-2') -> object:
    """Get boto3 client service."""
    # root org account doesn't have the IAM Role used in the child accounts
    if account_id != config.SERVICE_ACCOUNT_ID:
        # Assume service role on target AWS account
        sts_obj = StsObject(
            config.SESSION,
            account_id,
            config.SERVICE_ROLE_NAME
        )
        # Set boto3 resource using STS credentials
        resource = sts_obj.get_resource(service, region)
    else:
        # The service account is already authenticated with user's IAM role
        resource = config.SESSION.resource(service, region)

    return resource


def get_active_accounts() -> list:
    """Get the list of active AWS accounts in the Organization."""
    org = config.SESSION.client('organizations')
    excluded_accounts = []   # Add a list of Account IDs to be excluded
    for account in list(paginate(org, 'list_accounts')):
        # if account['Status'] == 'ACTIVE':
        if account['Status'] == 'ACTIVE' and account['Id'] not in excluded_accounts:
            yield {
                'AccountId': account['Id'],
                'AccountAlias': account['Name']
            }


def accounts_to_query(account_id: str) -> list:
    """Return a list with the AWS account/s where the query will run."""
    accounts = get_active_accounts()  # List of active AWS accounts in the Org
    if account_id != '111111111111':
        # check if the selected account belongs to the Org
        accounts = [get_dic_item(accounts, 'AccountId', account_id)]
        if accounts == [None]:
            LOGGER.error(
                'Account ID %s does not exist in the Organization.',
                account_id
            )
            leave(1)

    return accounts


def get_regions(account_id: str) -> list:
    """Gets Regions Enabled for the AWS Account."""
    ec2 = b3_client(account_id, 'ec2')
    try:
        response = ec2.describe_regions(AllRegions=False)
    except ClientError as e:
        LOGGER.error('Error getting list of regions: %s', e)
        return

    for region in response['Regions']:
        yield region['RegionName']


def regions_to_query(region: str, account_id: str) -> list:
    """Return a list with the AWS region/s where the query will run."""
    regions = get_regions(account_id)
    if region:
        if region in list(regions):
            regions = [region]
        else:
            LOGGER.error(
                'Region %s is not enabled with Account ID %s.',
                region,
                account_id
            )
            leave(1)

    return regions


def try_get_value(dictionary: dict, key: str) -> str:
    """Get value from dictionary if the key exist."""
    if ":" not in key:
        try:
            value = dictionary[key]
        except:  # pylint: disable=bare-except
            value = 'NoValue'
    else:
        r = ''
        dic_keys = key.split(':')
        if dic_keys[0] == 'DaysSince':
            try:
                value = get_days_since(dictionary[dic_keys[1]])
            except:  # pylint: disable=bare-except
                value = -1
        elif dic_keys[0] == 'DaysTo':
            try:
                value = get_days_to(dictionary[dic_keys[1]])
            except:  # pylint: disable=bare-except
                value = -1
        else:
            for k in dic_keys:  # Multiple dictionary keys
                r += "['" + k + "']"

            try:
                value = ast.literal_eval(f"dictionary{r}")
            except:  # pylint: disable=bare-except
                value = 'NoValue'

    return value


def get_resource_tags(resource: str) -> list:
    """Get list of default tag values if exist."""
    try:
        tags = Tag(resource['Tags'])
        r_tag = tags.values(config.MANDATORY_TAGS)
    except:  # pylint: disable=bare-except
        r_tag = list(config.MANDATORY_TAGS.values())
        r_tag.append(len(list(config.MANDATORY_TAGS.values())))

    return r_tag


def get_ec2_name(aws: dict, ec2_id: str) -> str:
    """Get EC2 instance name."""
    ec2 = b3_resource(aws['AccountId'], 'ec2', aws['Region'])
    instance = ec2.Instance(ec2_id)

    return get_tag_value(instance.tags, 'Name')


def get_ec2_platform(dictionary: dict, key: str) -> str:
    """Check if ec2 platform is Windows or Linux."""
    try:
        platform = dictionary[key]
    except:  # pylint: disable=bare-except
        platform = 'Linux'

    return platform


def get_ec2_instance_profile(dictionary: dict, key: str) -> str:
    """Check if ec2 have instance profile and return the ARN if any."""
    try:
        instance_profile = dictionary[key]
        instance_profile_arn = instance_profile['Arn']
    except:  # pylint: disable=bare-except
        instance_profile_arn = 'NoValue'

    return instance_profile_arn


def get_volume(client: object, ebs_mappings: list) -> int:
    """Get count and grant total size of EBS volumes."""
    volume_ids = []
    for v in ebs_mappings:
        volume_ids.append(v['Ebs']['VolumeId'])

    ebs_volumes = list(
        paginate(client, 'describe_volumes', VolumeIds=volume_ids)
    )
    ebs_total_size = 0
    for v in ebs_volumes:
        ebs_total_size += v['Size']

    return len(ebs_volumes), ebs_total_size


def get_backup_enabled_resources(client: object) -> list:
    """Get list of resource IDs enrolled to AWS Backup service."""
    for r in paginate(client, 'list_protected_resources'):
        if r['ResourceType'] == "EC2":
            arn = ArnHandler(r['ResourceArn'])
            yield arn.resource_id()


def get_patching_enabled_resources(client: object) -> list:
    """Get list of resource IDs enrolled to AWS SSM Patching service."""
    for pg in paginate(client, 'describe_patch_groups'):
        pg_instances = paginate(
            client,
            'describe_instance_patch_states_for_patch_group',
            PatchGroup=pg['PatchGroup']
        )
        for i in pg_instances:
            yield i['InstanceId']


def get_ssm_ec2_ids_inventory(client: object) -> list:
    """Get EC2 IDs from SSM inventory."""
    for i in paginate(client, 'describe_instance_information'):
        yield i['InstanceId']


def get_s3_tags(bucket: object) -> list:
    """Get s3 resource tags."""
    try:
        tags = bucket.tag_set
    except:  # pylint: disable=bare-except
        tags = None

    return tags


def get_user_tags(user: object) -> list:
    """Get User resource tags."""
    try:
        tags = user.tags
    except:  # pylint: disable=bare-except
        tags = None

    return tags


def get_last_used(access_key_access: dict) -> int:
    """Get number of days since last AccessKey usage."""
    try:
        return get_days_since(
            access_key_access['AccessKeyLastUsed']['LastUsedDate']
        )
    except:  # pylint: disable=bare-except
        return -1


def get_user_location(user: dict) -> str:
    """Get SSO user location."""
    try:
        return user['Addresses'][0]['Formatted']
    except:  # pylint: disable=bare-except
        return ''


def get_access_key(k: dict, client: object) -> str:
    """Get IAM User Access Key details."""
    key_id = k['AccessKeyId']
    status = k['Status']
    days_since_creation = get_days_since(k['CreateDate'])
    last_used = get_last_used(
        client.get_access_key_last_used(AccessKeyId=k['AccessKeyId'])
    )

    return key_id, status, days_since_creation, last_used


def get_iam_usr_policies(client: object, user: str) -> list:
    """Get Inline and Attached IAM policy names attached to a user."""
    user_policies = []
    inline_policies = client.list_user_policies(UserName=user)
    if inline_policies['PolicyNames']:
        user_policies = inline_policies['PolicyNames']

    # Grab User Policies: Atttached
    attached_policies = client.list_attached_user_policies(UserName=user)
    for pol in attached_policies['AttachedPolicies']:
        user_policies.append(pol['PolicyName'])

    return user_policies


def get_iam_usr_groups(client: object, user: str) -> list:
    """Get IAM group names a user belongs to and the policy names attached to
    the groups."""
    user_grp = []
    grp_policies = []

    user_groups = client.list_groups_for_user(UserName=user)
    for grp in user_groups['Groups']:
        user_grp.append(grp['GroupName'])

        # Grab IAM Policies associated which each group: Inline and Managed
        inline_grp_policies = client.list_group_policies(GroupName=grp['GroupName'])
        for policy in inline_grp_policies['PolicyNames']:
            grp_policies.append(policy)

        # Managed policies
        for policy in paginate(client, 'list_attached_group_policies', GroupName=grp['GroupName']):
            grp_policies.append(policy['PolicyName'])

    return user_grp, grp_policies


def get_arn_resources(resource_list: list, arn: str) -> list:
    """Get the ARN details and add it to the resources."""
    for r in resource_list:
        arn_object = ArnHandler(r[arn])
        r['ArnService'] = arn_object.service()
        r['ArnType'] = arn_object.resource_type()
        r['ArnId'] = arn_object.resource_id()
        yield r


def get_routes(route_list: list) -> list:
    """List routes as a string."""
    routes = ''
    for x in route_list:
        gateway = ''
        for key in x.keys():
            if 'Destination' in key:
                destination = x[key]

            if 'Id' in key:      # Targets
                gateway = x[key]

        # Fix when the target if it is an EC2 instance (i.e. NAT Instance)
        if 'InstanceOwnerId' in x.keys():
            gateway = f"{x['InstanceId']}-({x['InstanceOwnerId']})"

        # If no target was found try Core Network ARN
        if not gateway:
            gateway = try_get_value(x, 'CoreNetworkArn')

        # Gather the routes in a variable
        routes += f"{destination};{gateway};{x['Origin']};{x['State']}\n"

    return routes


def get_tgw_att_subnets(r: dict, client: object, resource: object) -> dict:
    """Get list of subnet IDs per TGW attachement."""
    if r['ResourceType'] == 'vpc':
        vpc_att = client.describe_transit_gateway_vpc_attachments(
            TransitGatewayAttachmentIds=[r['TransitGatewayAttachmentId']],
            Filters=[{'Name': 'vpc-id', 'Values': [r['ResourceId']]}]
        )
        subnets = ''
        for vpc_id in vpc_att['TransitGatewayVpcAttachments'][0]['SubnetIds']:
            try:
                sn = resource.Subnet(vpc_id)
                sn_az = sn.availability_zone
                try:
                    sn_tag_name = get_tag_value(sn.tags, 'Name')
                except:  # pylint: disable=bare-except
                    sn_tag_name = 'NoValue'

                subnets += f"{vpc_id}|{sn_az}|{sn_tag_name},"
            except:  # pylint: disable=bare-except
                subnets = None
    else:
        subnets = None

    return subnets


def get_dhcp_config(dhcp_configs: list, key: str) -> str:
    """Get DHCP Option configutations."""
    config_item = get_dic_item(dhcp_configs, 'Key', key)
    values = []
    if config_item:
        for value in config_item['Values']:
            values.append(value['Value'])

    return ' '.join(values)


def get_permission_set_detail(client: object, permission_set_arn: str) -> dict:
    """Generate a list of permission set detail."""
    response = client.describe_permission_set(
        InstanceArn=config.SSO_INSTANCE_ARN,
        PermissionSetArn=permission_set_arn
    )
    return response['PermissionSet']


def get_permission_set_details(client: object, permission_sets: list) -> list:
    """Generate a list of permission set details."""
    for p in permission_sets:
        yield get_permission_set_detail(client, p)


# ------------------------------------------------------------------------- #
# -------------------------------- Helpers -------------------------------- #
# ------------------------------------------------------------------------- #

def loop_function(items: list, f_to_call: object, flag: bool) -> list:
    """Run a function multiple times using parallel processing."""
    looper = Looper(items, f_to_call)
    return looper.parallel_return(summary=flag)


def add_region(aws: dict, regions: list) -> list:
    """Make up a list of dictionaries with AWS Account and Region details."""
    for region in regions:
        yield {
            'AccountId': aws['AccountId'],
            'AccountAlias': aws['AccountAlias'],
            'Region': region
        }


def abort_script(message) -> None:
    """Abort code execution."""
    LOGGER.error("Code execution aborted - %s", message)
    leave(1)


def get_tag_value(list_of_dic: list, key: str) -> dict:
    """Find a TAG from a list of TAGs and return the Value."""
    tag = next((item for item in list_of_dic if item['Key'] == key), None)
    if tag:
        return tag['Value']

    return 'NoValue'


def get_operating_system(platform: str) -> str:  # pylint: disable=too-many-branches
    """Translate platform name to operating system name for SSM api calls."""
    if platform == 'Amazon Linux':
        os_name = 'AMAZON_LINUX'
    elif platform == 'Amazon Linux AMI':
        os_name = 'AMAZON_LINUX'
    elif platform == 'Amazon Linux 2':
        os_name = 'AMAZON_LINUX_2'
    elif platform == 'Amazon Linux 2022':
        os_name = 'AMAZON_LINUX_2022'
    elif platform == 'Amazon Linux 2023':
        os_name = 'AMAZON_LINUX_2023'
    elif platform == 'Ubuntu':
        os_name = 'UBUNTU'
    elif platform == 'Debian':
        os_name = 'DEBIAN'
    elif platform == 'Suse':
        os_name = 'SUSE'
    elif platform == 'CentOS Linux':
        os_name = 'CENTOS'
    elif platform == 'CentOS':
        os_name = 'CENTOS'
    elif platform == 'Redhat Enterprise Linux':
        os_name = 'REDHAT_ENTERPRISE_LINUX'
    elif platform == 'RHEL':
        os_name = 'REDHAT_ENTERPRISE_LINUX'
    elif platform == 'Oracle Linux':
        os_name = 'ORACLE_LINUX'
    elif platform == 'Raspbian':
        os_name = 'RASPBIAN'
    elif platform == 'Rocky Linux':
        os_name = 'ROCKY_LINUX'
    elif platform == 'Alma Linux':
        os_name = 'ALMA_LINUX'
    elif platform == 'MacOS':
        os_name = 'MACOS'
    elif platform == 'Windows':
        os_name = 'WINDOWS'
    else:
        os_name = platform

    return os_name


def get_dic_item(list_of_dic: list, key: str, value: str) -> dict:
    """Find item from a list of dictionaries by key and value."""
    return next((item for item in list_of_dic if item[key] == value), None)


def byte_to_gb(size: int):
    """Tranform Bytes to GBs."""
    return size / 1024 / 1024 / 1024


def byte_to_mb(size: int):
    """Tranform Bytes to MBs."""
    return size / 1024 / 1024


def byte_to_kb(size: int):
    """Tranform Bytes to KBs."""
    return size / 1024


def format_date(date_field: datetime) -> str:
    """Format date field into string like DD/MM/YYYY HH:MM:SS UTC."""
    return datetime.strptime(str(date_field), '%Y-%m-%d %H:%M:%S%z').strftime('%-d/%m/%y %-H:%M')


def get_days_since(date: str) -> int:
    """Count days since today to a specific."""
    if isinstance(date, str):
        get_date_obj = parse(date)
        date_obj = get_date_obj.replace(tzinfo=None)
    else:
        date_obj = date.replace(tzinfo=None)

    diff = datetime.now() - date_obj
    return diff.days


def get_days_to(date: str) -> int:
    """Count days since specific date to today."""
    if isinstance(date, str):
        get_date_obj = parse(date)
        date_obj = get_date_obj.replace(tzinfo=None)
    else:
        date_obj = date.replace(tzinfo=None)

    diff = date_obj - datetime.now()
    return diff.days


# ------------------------------------------------------------------------- #
# ------------------------------ Paginator -------------------------------- #
# ------------------------------------------------------------------------- #

def paginate(client: object, method: str, **kwargs) -> list:
    """Paginate boto3 client methods."""
    try:
        paginator = client.get_paginator(method)
    except ClientError as e:
        LOGGER.error('Fail getting paginator : %s', e)
        return

    try:
        for page in paginator.paginate(**kwargs).result_key_iters():
            for result in page:
                yield result

    except ClientError as e:
        LOGGER.error('Pagination failure: %s', e)
        return
