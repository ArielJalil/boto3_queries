# -*- coding: utf-8 -*-
"""Helper functions for Looper class."""

import logging
import helpers.config as config

from classes.looper           import Looper
from helpers                  import MANDATORY_TAGS, SETUP, IDENTITY_STORE_ID
from helpers.resource_queries import *
from helpers.list_func        import is_in_the_list, get_dic_item
from helpers.boto3_func       import get_boto3_client, get_boto3_resource, paginate, \
                                     get_tags, get_tag_values, get_tag_value_by_key, \
                                     get_regions, format_date

LOGGER = logging.getLogger(__name__)


def loop_function(items: list, f_to_call: object, flag: bool) -> list:
    """Run a function using parallel processing."""
    looper = Looper(items, f_to_call)
    return looper.parallel_return(summary=flag)


def query_by_account(aws: dict) -> list:
    """Trigger a query at each active region by AWS account in parallel."""
    # Check if the AWS service is multi-region or not
    try:
        regions = SETUP[config.QUERY]['Region']
    except:
        regions = get_regions(str(aws['AccountId']))

    # Generate a list with all available regions for the service
    query_setups = make_aws_dic(
        aws,                                # AWS Account ID and Alias
        regions,                            # List of available regions
        SETUP[config.QUERY]['Client'],      # Boto3 client
        SETUP[config.QUERY]['Paginator'],   # Boto3 Paginator
        config.QUERY                        # Query name
    )

    return loop_function(query_setups, resource_query, False)


def make_aws_dic(aws: dict, regions: list, client: str, paginator: str, query: str) -> list:
    """Make a list of dictionaries with AWS Account and Region details."""
    accounts = list()
    for region in regions:
        accounts.append(
            {
                'AccountId': aws['AccountId'],
                'AccountAlias': aws['AccountAlias'],
                'Region': region,
                'Boto3Client': client,
                'Paginator': paginator,
                'QueryName': query
            }
        )

    return accounts


def make_list_acc_region(aws: dict, regions: list) -> list:
    """Make a list of dictionaries with AWS Account and Region details."""
    accounts = list()
    for region in regions:
        accounts.append(
            {
                'AccountId': aws['AccountId'],
                'AccountAlias': aws['AccountAlias'],
                'Region': region
            }
        )

    return accounts


def resource_query(aws:dict) -> list:
    """Run query with an AWS account and region."""
    # Initialize list of rows for the CSV output file
    csv_rows = list()

    # Get the resources to query from a paginator
    resources = paginator_selector(aws)

    # Loop through aws resources
    for r in resources:
        # Write CSV column row
        csv_row = [
            str(aws['AccountId']),
            aws['AccountAlias'],
            aws['Region']
        ]

        # Add resource columns from resource_queries.py
        csv_row += eval(aws['QueryName'])(r)    # QueryName and function should have the same name

        # Add tagging column values
        resource_tags = get_tags(r, MANDATORY_TAGS.copy())
        csv_row += get_tag_values(resource_tags)

        # Add new row to CSV file
        csv_rows.append(csv_row)

    return csv_rows


def get_tgw_att_subnets(r, client, resource) -> dict:
    """Get list of subnet IDs per TGW attachement."""
    if r['ResourceType'] == 'vpc':
        vpc_att = client.describe_transit_gateway_vpc_attachments(
            TransitGatewayAttachmentIds=[
                r['TransitGatewayAttachmentId']
            ],
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [
                        r['ResourceId']
                    ]
                }
            ]
        )
        subnets = ''
        for id in vpc_att['TransitGatewayVpcAttachments'][0]['SubnetIds']:
            try:
                sn = resource.Subnet(id)
                sn_az = sn.availability_zone
                try:
                    sn_tag_name = get_tag_value_by_key(sn.tags, 'Name')
                except:
                    sn_tag_name = 'NoValue'

                subnets += f"{id},{sn_az},{sn_tag_name},"
            except:
                pass
    else:
        subnets = None

    return subnets


def get_backup_enabled_resources(client: object) -> list:
    """Get list of resource IDs enrolled to AWS Backup service."""
    ec2_ids = []
    for r in list(paginate(client, 'list_protected_resources')):
        if r['ResourceType'] == "EC2":
            arn = ArnHandler(r['ResourceArn'])
            ec2_ids.append(arn.resource_id())

    return ec2_ids


def get_patching_enabled_resources(client: object) -> list:
    """Get list of resource IDs enrolled to AWS SSM Patching service."""
    ec2_ids = []
    for pg in list(paginate(client, 'describe_patch_groups')):
        pg_instances = paginate(
            client,
            'describe_instance_patch_states_for_patch_group',
            PatchGroup=pg['PatchGroup']
        )
        for i in pg_instances:
            ec2_ids.append(i['InstanceId'])

    return ec2_ids


def get_ssm_inventory(client: object) -> list:
    """Get EC2 IDs from SSM inventory."""
    ec2_ids = []
    for i in list(paginate(client, 'describe_instance_information')):
        ec2_ids.append(i['InstanceId'])

    return ec2_ids


def get_volume(client, ebs_mappings):
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
    except:
        return -1


def paginator_selector(aws: dict) -> list:
    """Get the list fields of interest in a list."""
    resources = list()

    # Get boto3 client per region
    client = get_boto3_client(aws['AccountId'], aws['Boto3Client'], region=aws['Region'])

    if aws['QueryName'] == 'ec2':
        # Set boto3 client for other services required in the query
        bkp = get_boto3_client(aws['AccountId'], 'backup', region=aws['Region'])
        ssm = get_boto3_client(aws['AccountId'], 'ssm', region=aws['Region'])

        # Get list of instances enrolled for other services
        bkp_ena_ids   = get_backup_enabled_resources(bkp)
        patch_ena_ids = get_patching_enabled_resources(ssm)
        ssm_inventory = get_ssm_inventory(ssm)

        # Filter to Grab all but terminated EC2 instances in the AWS account and region
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
        for ec2s in list(paginate(client, aws['Paginator'], Filters=ec2_filter)):
            for r in ec2s['Instances']:
                # Add extra values to the EC2 resource query
                r['IsAwsBuckupEnabled'] = is_in_the_list(bkp_ena_ids, r['InstanceId'])
                r['IsSsmPatchEnabled'] = is_in_the_list(patch_ena_ids, r['InstanceId'])
                r['IsSsmAgentEnabled'] = is_in_the_list(ssm_inventory, r['InstanceId'])
                r['VolumeCount'], r['VolumeSize'] = get_volume(client, r['BlockDeviceMappings'])

                resources.append(r)

    elif aws['QueryName'] == 'tgw_attach':
        ec2r = get_boto3_resource(aws['AccountId'], aws['Boto3Client'], region=aws['Region'])
        for r in list(paginate(client, aws['Paginator'])):
            r['Subnets'] = get_tgw_att_subnets(r, client, ec2r)
            resources.append(r)

    elif aws['QueryName'] == 'ebs_volume_snap':
        resources = list(paginate(client, aws['Paginator'], OwnerIds=[aws['AccountId']]))

    elif aws['QueryName'] == 'aws_config':
        resources = list(paginate(client, aws['Paginator'], resourceType='AWS::EC2::Instance', includeDeletedResources=False))

    elif aws['QueryName'] == 'vpn':
        response = client.describe_vpn_connections()
        resources = response['VpnConnections']

    elif aws['QueryName'] == 'dx_vgw':
        response = client.describe_virtual_gateways()
        resources = response['virtualGateways']

    elif aws['QueryName'] == 'dx_vif':
        response = client.describe_virtual_interfaces()
        resources = response['virtualInterfaces']

    elif aws['QueryName'] == 'ram':
        response = client.list_resources(
            resourceOwner='SELF',
            resourceRegionScope='REGIONAL'
        )
        resources = response['resources']

    elif aws['QueryName'] == 'ssm_patching':
        for pg in list(paginate(client, 'describe_patch_groups')):
            for i in list(paginate(client, aws['Paginator'], PatchGroup=pg['PatchGroup'])):
                i['OperatingSystem'] = pg['BaselineIdentity']['OperatingSystem']
                resources.append(i)

    elif aws['QueryName'] == 's3_bucket':
        response = client.list_buckets()
        resource = get_boto3_resource(aws['AccountId'], 's3')
        for b in response['Buckets']:
            tags = resource.BucketTagging(b['Name'])
            try:
                b['Tags'] = tags.tag_set
            except:
                b['Tags'] = None

            resources.append(b)

    elif aws['QueryName'] == 'iam_user':
        response = list(paginate(client, aws['Paginator']))
        resource = get_boto3_resource(aws['AccountId'], 'iam')
        for r in response:
            user = resource.User(r['UserName'])

            # Get last time password was used
            try:
                pass_last_used = format_date(r['PasswordLastUsed'])     # format like DD/MM/YYYY HH:MM
                days_since_last_login = get_days_since(r['PasswordLastUsed'])
            except:
                pass_last_used = 'Never used'
                days_since_last_login = -1

            user_policies = list()
            # Grab User Policies: Inline and Atttached
            inline_policies = client.list_user_policies(UserName=r['UserName'])
            if inline_policies['PolicyNames']:
                user_policies = inline_policies['PolicyNames']

            attached_policies = client.list_attached_user_policies(UserName=r['UserName'])
            for pol in attached_policies['AttachedPolicies']:
                user_policies.append(pol['PolicyName'])

            # Check Access Keys status
            accesss_key_1 = None
            status_key_1 = None
            days_since_creation_key_1 = None
            last_used_key_1 = None
            accesss_key_2 = None
            status_key_2 = None
            days_since_creation_key_2 = None
            last_used_key_2 = None
            access_keys = list(paginate(client, 'list_access_keys', UserName=r['UserName']))
            if access_keys:
                for i in range(2):
                    if access_keys:
                        k = access_keys.pop()
                        if i == 0:
                            accesss_key_1 = k['AccessKeyId']
                            status_key_1 = k['Status']
                            days_since_creation_key_1 = get_days_since(k['CreateDate'])
                            last_used_key_1 = get_last_used(
                                client.get_access_key_last_used(AccessKeyId=k['AccessKeyId'])
                            )
                        if i == 1:
                            accesss_key_2 = k['AccessKeyId']
                            status_key_2 = k['Status']
                            days_since_creation_key_2 = get_days_since(k['CreateDate'])
                            last_used_key_2 = get_last_used(
                                client.get_access_key_last_used(AccessKeyId=k['AccessKeyId'])
                            )

            # Grab the IAM groups attached to this user
            user_grp = list()
            user_groups = client.list_groups_for_user(UserName=r['UserName'])
            # Loop through IAM groups associated with the IAM user
            for grp in user_groups['Groups']:
                user_grp.append(grp['GroupName'])

                # Grab the IAM Policies associated which each group: Inline and Managed
                inline_grp_policies = client.list_group_policies(GroupName=grp['GroupName'])
                if inline_grp_policies['PolicyNames']:
                    for policy in inline_grp_policies['PolicyNames']:
                        user_policies.append(policy)

                managed_grp_policies = list(
                    paginate(client, 'list_attached_group_policies', GroupName=grp['GroupName'])
                )
                for policy in managed_grp_policies:
                    user_policies.append(policy['PolicyName'])

            r['pass_last_used'] = pass_last_used
            r['days_since_last_login'] = days_since_last_login
            r['accesss_key_1'] = accesss_key_1
            r['status_key_1'] = status_key_1
            r['days_since_creation_key_1'] = days_since_creation_key_1
            r['last_used_key_1'] = last_used_key_1
            r['accesss_key_2'] = accesss_key_2
            r['status_key_2'] = status_key_2
            r['days_since_creation_key_2'] = days_since_creation_key_2
            r['last_used_key_2'] = last_used_key_2
            r['user_grp'] = user_grp
            r['user_policies'] = user_policies

            try:
                r['Tags'] = user.tags
            except:
                r['Tags'] = None

            resources.append(r)

    elif aws['QueryName'] == 'iam_sso_user':
        # sso = get_boto3_client(aws['AccountId'], 'sso-admin', region=aws['Region'])
        # pprint(list(paginate(sso, 'list_instances')))
        sso_groups = list(paginate(client, 'list_groups', IdentityStoreId=IDENTITY_STORE_ID))
        resources = list()
        for user in paginate(client, aws['Paginator'], IdentityStoreId=IDENTITY_STORE_ID):
            group_ids = list()
            for group_id in paginate(
                    client,
                    'list_group_memberships_for_member',
                    IdentityStoreId=IDENTITY_STORE_ID,
                    MemberId={'UserId': user['UserId']}
                ):
                sso_group = get_dic_item(sso_groups, 'GroupId', group_id['GroupId'])
                group_ids.append(sso_group['DisplayName'])

            user['GroupIds'] = group_ids
            resources.append(user)

    elif aws['QueryName'] == 'iam_sso_group':
        resources = list(paginate(client, aws['Paginator'], IdentityStoreId=IDENTITY_STORE_ID))

    else:
        resources = list(paginate(client, aws['Paginator']))

    return resources
