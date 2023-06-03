# -*- coding: utf-8 -*-
"""General useful functions to support boto3 api calls."""

from sys                 import exit
from logging             import getLogger
from datetime            import datetime
from dateutil.parser     import parse
from botocore.exceptions import ClientError, SSOTokenLoadError, \
                                UnauthorizedSSOTokenError

from classes.assume_role import StsObject
from classes.arn_handler import ArnHandler

from helpers.list_func   import get_dic_item
import helpers.config    as config

LOGGER = getLogger(__name__)


def abort_script(message) -> None:
    """Abort code execution."""
    print(f"\n INTERRUPTED !!!\n")
    LOGGER.error(f"Code execution aborted - {message}")
    exit(1)


def validate_sts_token():
    """Check if the user running the query is authenticated."""
    sts = get_boto3_client(config.SERVICE_ACCOUNT_ID, 'sts')

    try:
        caller = sts.get_caller_identity()
    except UnauthorizedSSOTokenError as erro:
        abort_script(erro)
    except SSOTokenLoadError as erro:
        abort_script(erro)

    return caller


def get_boto3_client(account_id: str, service: str, region=config.REGION) -> object:
    """Get boto3 client service."""
    # root organization account doesn't have the IAM Role used in the child accounts
    if account_id != config.SERVICE_ACCOUNT_ID:
        # Assume service role on target AWS account
        sts_obj = StsObject(config.SESSION, account_id, config.SERVICE_ROLE_NAME)

        # Set boto3 client using STS credentials
        client = sts_obj.get_client(service, region)
    else:
        # The service account is already authenticated and it will use user's IAM role
        client = config.SESSION.client(service, region)

    return client


def get_boto3_resource(account_id: str, service: str, region='ap-southeast-2') -> object:
    """Get boto3 client service."""
    # root organization account doesn't have the IAM Role used in the child accounts
    if account_id != config.SERVICE_ACCOUNT_ID:
        # Assume service role on target AWS account
        sts_obj = StsObject(config.SESSION, account_id, config.SERVICE_ROLE_NAME)
        # Set boto3 resource using STS credentials
        resource = sts_obj.get_resource(service, region)
    else:
        # The service account is already authenticated and it will use user's IAM role
        resource = config.SESSION.resource(service, region)

    return resource


def get_active_accounts() -> list:
    """Get the list of active AWS accounts in the Organization."""
    aws_accounts_id_alias = list()
    if (org := config.SESSION.client('organizations')):
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


def get_regions(account_id: str) -> list:
    """Gets Regions Enabled for the AWS Account."""
    regions = list()
    ec2 = get_boto3_client(account_id, 'ec2')
    try:
        response = ec2.describe_regions(AllRegions=False)

        for region in response['Regions']:
            regions.append(region['RegionName'])

    except ClientError as e:
        message = 'Error getting list of regions: {}'.format(e)
        LOGGER.error(message)

    return regions


def paginate(client: object, method: str, **kwargs) -> list:
    """Paginate boto3 client methods."""
    try:
        paginator = client.get_paginator(method)
    except ClientError as e:
        message = 'Paginator failed: {}'.format(e)
        LOGGER.error(message)
        return

    try:
        for page in paginator.paginate(**kwargs).result_key_iters():
            for result in page:
                yield result

    except ClientError as e:
        message = 'Pagination failed: {}'.format(e)
        LOGGER.error(message)


def get_ec2_name(aws: dict, id: str) -> str:
    """Get EC2 instance name."""
    ec2 = get_boto3_resource(aws['AccountId'], 'ec2', aws['Region'])
    instance = ec2.Instance(id)
    ec2_tag = get_dic_item(instance.tags, 'Key', 'Name')
    return ec2_tag['Value']


def get_value_if_any(dictionary: dict, key: str) -> str:
    """Look for a dictionary key and return its value if exist."""
    if key in dictionary.keys():
        value = dictionary[key]
    else:
        value = 'NoValue'

    return value


def try_get_value(dictionary: dict, key: str) -> str:
    """Get value from dictionary if the key exist."""
    if ":" in key:
        r = ''
        dic_keys = key.split(':')
        if dic_keys[0] == 'DaysSince':
            try:
                value = get_days_since(dictionary[dic_keys[1]])
            except: # pylint: disable=broad-except
                value = -1
        else:
            # Multiple dictionary keys
            for k in dic_keys:
                r += "['" + k + "']"

            try:
                value = eval(f"dictionary{r}")
            except: # pylint: disable=broad-except
                value = 'NoValue'
    else:
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


def get_all_tags(aws_response: dict) -> list:
    """Get mandatory TAGs if those are set."""
    tags = []
    try:
        for t in aws_response['Tags']:
            # tags.append(f"{t['Key']} | {t['Value']}")
            tags.append(t['Key'])
    except: # pylint: disable=broad-except
        pass

    return tags


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
    key_pair = next((tag for tag in tags if tag['Key'] == key_value), None)
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
    tag_values = list()
    count_missing_tags = 0
    for t in tags.keys():
        tag_values.append(tags[t])
        if tags[t] == 'NoValue':
            count_missing_tags += 1

    tag_values.append(count_missing_tags)

    return tag_values


def get_tag_keys(tags: dict) -> list:
    """Get tag key names."""
    tag_keys = list()
    for t in tags.keys():
        tag_keys.append(t)

    tag_keys.append('Count of Missing TAGs')

    return tag_keys


def format_date(date_field: datetime) -> str:
    """Format date field into string like DD/MM/YYYY HH:MM."""
    return datetime.strptime(str(date_field), '%Y-%m-%d %H:%M:%S%z').strftime('%-d/%m/%y %-H:%M')


def get_days_since(date: str) -> int:
    """Count days since specific date to today."""
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


def get_operating_system(platform: str) -> str:
    """Translate platform name to operating system name for SSM api calls."""

    if   platform == 'Amazon Linux':            os_name = 'AMAZON_LINUX'
    elif platform == 'Amazon Linux AMI':        os_name = 'AMAZON_LINUX'
    elif platform == 'Amazon Linux 2':          os_name = 'AMAZON_LINUX_2'
    elif platform == 'Amazon Linux 2022':       os_name = 'AMAZON_LINUX_2022'
    elif platform == 'Amazon Linux 2023':       os_name = 'AMAZON_LINUX_2023'
    elif platform == 'Ubuntu':                  os_name = 'UBUNTU'
    elif platform == 'Debian':                  os_name = 'DEBIAN'
    elif platform == 'Suse':                    os_name = 'SUSE'
    elif platform == 'CentOS Linux':            os_name = 'CENTOS'
    elif platform == 'CentOS':                  os_name = 'CENTOS'
    elif platform == 'Redhat Enterprise Linux': os_name = 'REDHAT_ENTERPRISE_LINUX'
    elif platform == 'RHEL':                    os_name = 'REDHAT_ENTERPRISE_LINUX'
    elif platform == 'Oracle Linux':            os_name = 'ORACLE_LINUX'
    elif platform == 'Raspbian':                os_name = 'RASPBIAN'
    elif platform == 'Rocky Linux':             os_name = 'ROCKY_LINUX'
    elif platform == 'Alma Linux':              os_name = 'ALMA_LINUX'
    elif platform == 'MacOS':                   os_name = 'MACOS'
    elif platform == 'Windows':                 os_name = 'WINDOWS'
    else:
        os_name = platform

    return os_name


def get_volume(client: object, ebs_mappings: list) -> int:
    """Get count and grant total size of EBS volumes."""
    volume_ids = list()
    for v in ebs_mappings:
        volume_ids.append(v['Ebs']['VolumeId'])

    ebs_volumes = list(paginate(client, 'describe_volumes', VolumeIds=volume_ids))
    ebs_total_size = 0
    for v in ebs_volumes:
        ebs_total_size += v['Size']

    return len(ebs_volumes), ebs_total_size


def get_last_used(access_key_access: dict) -> int:
    """Get number of days since last AccessKey usage."""
    try:
        return get_days_since(access_key_access['AccessKeyLastUsed']['LastUsedDate'])
    except: # pylint: disable=broad-except
        return -1


def get_user_location(user: dict) -> str:
    """Get SSO user location."""
    try:
        return user['Addresses'][0]['Formatted']
    except: # pylint: disable=broad-except
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


def get_arn_resources(resource_list: list, arn: str) -> list:
    """Get the ARN details and add it to the resources."""
    resources = []
    for r in resource_list:
        arn_object = ArnHandler(r[arn])
        r['ArnService'] =  arn_object.service()
        r['ArnType'] = arn_object.resource_type()
        r['ArnId'] = arn_object.resource_id()
        resources.append(r)

    return resources


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
        for id in vpc_att['TransitGatewayVpcAttachments'][0]['SubnetIds']:
            try:
                sn = resource.Subnet(id)
                sn_az = sn.availability_zone
                try:
                    sn_tag_name = get_tag_value_by_key(sn.tags, 'Name')
                except: # pylint: disable=broad-except
                    sn_tag_name = 'NoValue'

                subnets += f"{id},{sn_az},{sn_tag_name},"
            except: # pylint: disable=broad-except
                pass
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


def get_backup_enabled_resources(client: object) -> list:
    """Get list of resource IDs enrolled to AWS Backup service."""
    ec2_ids = []
    for r in paginate(client, 'list_protected_resources'):
        if r['ResourceType'] == "EC2":
            arn = ArnHandler(r['ResourceArn'])
            ec2_ids.append(arn.resource_id())

    return ec2_ids


def get_patching_enabled_resources(client: object) -> list:
    """Get list of resource IDs enrolled to AWS SSM Patching service."""
    ec2_ids = []
    for pg in paginate(client, 'describe_patch_groups'):
        pg_instances = paginate(
            client,
            'describe_instance_patch_states_for_patch_group',
            PatchGroup=pg['PatchGroup']
        )
        for i in pg_instances:
            ec2_ids.append(i['InstanceId'])

    return ec2_ids


def get_ssm_ec2_ids_inventory(client: object) -> list:
    """Get EC2 IDs from SSM inventory."""
    return [i['InstanceId'] for i in paginate(client, 'describe_instance_information')]


def get_permission_set_detail(client: object, permission_set_arn: str) -> dict:
    """Generate a list of permission set detail."""
    response = client.describe_permission_set(
        InstanceArn=config.SSO_INSTANCE_ARN,
        PermissionSetArn=permission_set_arn
    )
    return response['PermissionSet']


def get_permission_set_details(client: object, permission_sets: list) -> list:
    """Generate a list of permission set details."""
    ps = list()
    for p in permission_sets:
        ps.append(get_permission_set_detail(client, p))

    return ps
