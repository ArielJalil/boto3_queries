# -*- coding: utf-8 -*-
"""General useful functions to support boto3 api calls."""

import sys
from logging import getLogger
from helpers import SETUP, config
from classes.python_sdk import Paginator, AwsPythonSdk
from classes.python_arrays import GetItemFrom
from classes.arn_handler import ArnHandler
from classes.common import AwsDate, ByteTo
from classes.cw_metric import CwMetric
from classes.tag import Tag

LOGGER = getLogger(__name__)


def accounts_to_query(account_id: str) -> list:
    """Return a list with the AWS account/s where the query will run."""
    # List of active AWS accounts in the Org
    accounts = AwsPythonSdk(config.ROOT_ACCOUNT_ID, 'organizations').org_accounts()
    if account_id != '111111111111':
        # check if the selected account belongs to the Org
        accounts = [GetItemFrom(accounts).by_key_pair('AccountId', account_id)]
        if accounts == [None]:
            LOGGER.error("Account ID %s does not exist in the Organization.", account_id)
            sys.exit(-1)

    return accounts


def regions_to_query(region: str, account_id: str) -> list:
    """Return a list with the AWS region/s where the query will run."""
    regions = AwsPythonSdk(account_id, 'ec2').get_regions()
    if region:
        if region in list(regions):
            regions = [region]
        else:
            LOGGER.error("Region %s is not enabled with Account ID %s.", region, account_id)
            sys.exit(-1)

    return regions


def add_region(aws: dict, regions: list) -> any:
    """Make up a list of dictionaries with AWS Account and Region details."""
    for region in regions:
        yield {
            'AccountId': aws['AccountId'],
            'AccountAlias': aws['AccountAlias'],
            'Region': region
        }


def get_resource_tags(resource: str) -> list:
    """Get list of default tag values if exist and count missing tags."""
    try:
        r_tag = Tag(resource['Tags']).values(config.MANDATORY_TAGS)
    except KeyError:
        r_tag = list(config.MANDATORY_TAGS.values())
        r_tag.append(len(config.TAG_KEYS))

    return r_tag


# / ################ \ #
#                      #
# | Resource helpers | #
#                      #
# \ ################ / #


def try_get_value(dictionary: dict, key: str) -> str:
    """Get value from dictionary if the key exist."""
    if ":" not in key:
        try:
            value = dictionary[key]
        except KeyError:
            value = 'HeaderNotFound'
    else:
        r = ''
        dic_keys = key.split(':')
        if dic_keys[0] == 'DaysSince':
            try:
                value = AwsDate(dictionary[dic_keys[1]]).days_since()
            except:  # pylint: disable=W0702
                value = -1
        elif dic_keys[0] == 'DaysTo':
            try:
                value = AwsDate(dictionary[dic_keys[1]]).days_to()
            except:  # pylint: disable=W0702
                value = -1
        else:
            for k in dic_keys:  # Multiple dictionary keys
                r += "['" + k + "']"

            try:
                value = eval(f"dictionary{r}")  # nosec: B307
            except KeyError:
                value = 'HeaderNotFound'

    return value


def get_ec2_platform(dictionary: dict, key: str) -> str:
    """Check if ec2 platform is Windows or Linux."""
    try:
        platform = dictionary[key]
    except KeyError:
        platform = 'Linux'

    return platform


def get_s3_tags(bucket: object) -> list:
    """Get s3 resource tags."""
    try:
        tags = bucket.tag_set
    except:  # pylint: disable=W0702
        tags = None

    return tags


def get_user_tags(user: object) -> list:
    """Get User resource tags."""
    try:
        tags = user.tags
    except:  # pylint: disable=W0702
        tags = None

    return tags


def get_dx_gw_attach(query: str, client: object, boto3_method: object) -> any:
    """Run DX Gateway attachments query."""
    b3_method_dx_gw = getattr(client, 'describe_direct_connect_gateways')
    dx_gws = b3_method_dx_gw()
    dx_gw_ids = [dx['directConnectGatewayId'] for dx in dx_gws['directConnectGateways']]

    for dx_gw_id in dx_gw_ids:
        response = boto3_method(directConnectGatewayId=dx_gw_id)
        for attach in response[SETUP[query]['ResponseItem']]:
            yield attach


def s3_bucket_query(aws: dict, query: str, boto3_method: object) -> any:
    """Run S3 bucket query."""
    s3 = AwsPythonSdk(aws['AccountId'], 's3').resource()
    cw = AwsPythonSdk(aws['AccountId'], 'cloudwatch').client()
    cw_metric = CwMetric(cw)
    response = boto3_method()
    for b in response[SETUP[query]['ResponseItem']]:
        b['CreationDate'] = b['CreationDate'].strftime('%c')
        metric = cw_metric.get_bucket_size(b['Name'])
        print(metric)
        b['CustomSizeGB'] = ByteTo(metric['Value']).giga()
        metric = cw_metric.get_bucket_object_count(b['Name'])
        print(metric)
        b['CustomObjectCount'] = metric['Value']
        tags = s3.BucketTagging(b['Name'])
        b['Tags'] = get_s3_tags(tags)

        yield b


def get_ec2_instance_profile(dictionary: dict, key: str) -> str:
    """Check if ec2 have instance profile and return the ARN if any."""
    try:
        instance_profile = dictionary[key]
        instance_profile_arn = instance_profile['Arn']
    except KeyError:
        instance_profile_arn = 'NoValue'

    return instance_profile_arn


def get_ec2_sec_grps(net_ifs: list) -> list:
    """Get the list of Security Groups attached to an EC2 instance per ENI."""
    result = []
    for eni in net_ifs:
        for sg in eni['Groups']:
            result.append(f"{sg['GroupId']}|{sg['GroupName']}")

    return result


def get_volume(client: object, ebs_mappings: list) -> int:
    """Get count and grant total size of EBS volumes."""
    volume_ids = []
    for v in ebs_mappings:
        volume_ids.append(v['Ebs']['VolumeId'])

    ebs_volumes = Paginator(client, 'describe_volumes').paginate(VolumeIds=volume_ids)
    vol_count = 0
    ebs_total_size = 0
    for v in ebs_volumes:
        vol_count += 1
        ebs_total_size += v['Size']

    return vol_count, ebs_total_size


def get_backup_enabled_resources(client: object) -> any:
    """Get list of resource IDs enrolled to AWS Backup service."""
    for r in Paginator(client, 'list_protected_resources').paginate():
        if r['ResourceType'] == "EC2":
            arn = ArnHandler(r['ResourceArn'])
            yield arn.resource_id()


def get_patching_enabled_resources(client: object) -> any:
    """Get list of resource IDs enrolled to AWS SSM Patching service."""
    for pg in Paginator(client, 'describe_patch_groups').paginate():
        pg_instances = Paginator(
            client,
            'describe_instance_patch_states_for_patch_group'
        ).paginate(PatchGroup=pg['PatchGroup'])

        for i in pg_instances:
            yield i['InstanceId']


def get_last_used(access_key_access: dict) -> int:
    """Get number of days since last AccessKey usage."""
    try:
        return AwsDate(access_key_access['AccessKeyLastUsed']['LastUsedDate']).days_since()
    except:  # pylint: disable=W0702
        return -1


def get_user_location(user: dict) -> str:
    """Get SSO user location."""
    try:
        return user['Addresses'][0]['Formatted']
    except KeyError:
        return ''


def get_access_key(k: dict, client: object) -> str:
    """Get IAM User Access Key details."""
    key_id = k['AccessKeyId']
    status = k['Status']
    days_since_creation = AwsDate(k['CreateDate']).days_since()
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

        # Grab the IAM Policies associated which each group: Inline and Managed
        inline_grp_policies = client.list_group_policies(GroupName=grp['GroupName'])
        for policy in inline_grp_policies['PolicyNames']:
            grp_policies.append(policy)

        # Managed policies
        for policy in Paginator(client, 'list_attached_group_policies').paginate(GroupName=grp['GroupName']):  # pylint: disable=C0301
            grp_policies.append(policy['PolicyName'])

    return user_grp, grp_policies


def get_arn_resources(resource_list: list, arn: str) -> any:
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

            if 'Id' in key:  # Targets
                gateway = x[key]

        # Fix when the target if it is an EC2 instance (i.e. NAT Instance)
        if 'InstanceOwnerId' in x.keys():
            gateway = f"{x['NetworkInterfaceId']}-({x['InstanceId']})-({x['InstanceOwnerId']})"

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
        for subnet_id in vpc_att['TransitGatewayVpcAttachments'][0]['SubnetIds']:
            try:
                sn = resource.Subnet(subnet_id)
                sn_az = sn.availability_zone
                sn_tag_name = GetItemFrom(sn.tags).by_tag_key('Name')
                if not sn_tag_name:
                    sn_tag_name = 'NoValue'

                subnets += f"{subnet_id}|{sn_az}|{sn_tag_name},"
            except:  # pylint: disable=W0702  # nosec B110
                pass
    else:
        subnets = None

    return subnets


def get_dhcp_config(dhcp_configs: list, key: str) -> str:
    """Get DHCP Option configutations."""
    config_item = GetItemFrom(dhcp_configs).by_key_pair('Key', key)
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


def get_permission_set_details(client: object, permission_sets: list) -> any:
    """Generate a list of permission set details."""
    for p in permission_sets:
        yield get_permission_set_detail(client, p)


def get_operating_system(platform: str) -> str:  # pylint: disable=R0912
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
