# -*- coding: utf-8 -*-
"""Helper functions for Looper class."""

from logging            import getLogger
from classes.looper     import Looper

from helpers.list_func  import is_in_the_list, get_dic_item
from helpers.boto3_func import *
from helpers            import SETUP
import helpers.config   as     config

LOGGER = getLogger(__name__)


def loop_function(items: list, f_to_call: object, flag: bool) -> list:
    """Run a function using parallel processing."""
    looper = Looper(items, f_to_call)
    return looper.parallel_return(summary=flag)


def make_aws_dic(aws: dict, regions: list, client: str, paginator: str, query: str) -> list:
    """Make up a list of dictionaries with AWS Account and Region details."""
    for region in regions:
        yield {
            'AccountId': aws['AccountId'],
            'AccountAlias': aws['AccountAlias'],
            'Region': region,
            'Boto3Client': client,
            'Paginator': paginator,
            'QueryName': query
        }


def make_list_acc_region(aws: dict, regions: list) -> list:
    """Make up a list of dictionaries with AWS Account and Region details."""
    for region in regions:
        yield {
            'AccountId': aws['AccountId'],
            'AccountAlias': aws['AccountAlias'],
            'Region': region
        }


def query_by_account(aws: dict) -> list:
    """Trigger a query at each active region by AWS account in parallel."""
    # Check if the query is multi-region or not
    try:
        regions = SETUP[config.QUERY]['Region']
    except: # pylint: disable=broad-except
        regions = get_regions(str(aws['AccountId']))

    # Generate a list with required region/s for the service
    queries_to_run = make_aws_dic(
        aws,                                # AWS Account ID and Alias
        regions,                            # List of available regions
        SETUP[config.QUERY]['Client'],      # Boto3 client
        SETUP[config.QUERY]['Paginator'],   # Boto3 Paginator
        config.QUERY                        # Query name
    )

    return loop_function(queries_to_run, resource_query, False)


def get_selected_fields(resource: dict) -> list:
    """Grab a single resource details of interest from the list of resources."""
    # Fields to be included in the CSV file output are set in helpers/__init__.py file
    for header in SETUP[config.QUERY]['Headers']:
        yield try_get_value(resource, header)


def resource_query(aws:dict) -> list:
    """Run query with an AWS account and region."""
    csv_rows = list()              # Initialize list of rows for the CSV output file
    resources = get_resources(aws) # Get the resources to query from a paginator

    # Loop through aws resources
    for r in resources:
        # Writing CSV row, starting with common values to all queries
        csv_row = [str(aws['AccountId']), aws['AccountAlias'], aws['Region']]

        # Add selected resource values to each row at the CSV file
        csv_row += get_selected_fields(r)

        # Add tagging column values
        resource_tags = get_tags(r, config.MANDATORY_TAGS.copy())
        csv_row += get_tag_values(resource_tags)
        csv_rows.append(csv_row) # Add new row for the CSV file

    return csv_rows


def get_resources(aws: dict) -> list:
    """Get the fields of interest in a list of dictionaries."""
    resources = list()  # Initialize variable

    # Get main boto3 object per query and region
    client = get_boto3_client(aws['AccountId'], aws['Boto3Client'], region=aws['Region'])

    # Make up queries to include values not included in the paginator or return paginator output as it is
    if aws['Paginator']:
        if aws['QueryName'] == 'ec2':
            # Set boto3 client for other services required in this query
            bkp = get_boto3_client(aws['AccountId'], 'backup', region=aws['Region'])
            ssm = get_boto3_client(aws['AccountId'], 'ssm', region=aws['Region'])

            # Get list of instances enrolled for other services
            bkp_ena_ids   = get_backup_enabled_resources(bkp)
            patch_ena_ids = get_patching_enabled_resources(ssm)
            ssm_inventory = get_ssm_ec2_ids_inventory(ssm)

            # Filter to Grab all but terminated EC2 instances in the AWS account and region
            ec2_filter = [
                {
                    'Name': 'instance-state-name',
                    'Values': ['pending', 'running', 'stopping', 'stopped']
                }
            ]

            # Add extra values to the EC2 paginator output
            for ec2s in paginate(client, aws['Paginator'], Filters=ec2_filter):
                for r in ec2s['Instances']:
                    r['IsAwsBuckupEnabled'] = is_in_the_list(bkp_ena_ids, r['InstanceId'])
                    r['IsSsmPatchEnabled'] = is_in_the_list(patch_ena_ids, r['InstanceId'])
                    r['IsSsmAgentEnabled'] = is_in_the_list(ssm_inventory, r['InstanceId'])
                    r['VolumeCount'], r['VolumeSize'] = get_volume(client, r['BlockDeviceMappings'])
                    r['Platform'] = get_ec2_platform(r, 'Platform')
                    r['IamInstanceProfile'] = get_instance_profile(r, 'IamInstanceProfile')

                    resources.append(r)

        elif aws['QueryName'] == 'ssm_patching':
            # Fetch all instances registered with SSM service
            ssm_inventory = list(paginate(client, 'describe_instance_information'))

            # Find instances enrolled to SSM patching per Patch Group and add extra values
            for pg in paginate(client, 'describe_patch_groups'):
                for i in paginate(client, aws['Paginator'], PatchGroup=pg['PatchGroup']):
                    i['CustomOperatingSystem'] = pg['BaselineIdentity']['OperatingSystem']
                    vm_from_inventory = get_dic_item(ssm_inventory, 'InstanceId', i['InstanceId'])
                    i['CustomName'] = try_get_value(vm_from_inventory, 'Name')
                    i['CustomComputerName'] = try_get_value(vm_from_inventory, 'ComputerName')
                    i['CustomPlatformVersion'] = try_get_value(vm_from_inventory, 'PlatformVersion')
                    if vm_from_inventory:
                        platform = get_operating_system(vm_from_inventory['PlatformName'])
                        i['CustomIsInSsmInventory'] = True
                    else:
                        i['CustomIsInSsmInventory'] = False

                    if i['CustomOperatingSystem'] == platform and i['CustomIsInSsmInventory'] == True:
                            resources.append(i)

        elif aws['QueryName'] == 'aws_config':
            # Adding arguments to paginator
            resources = paginate(
                client, aws['Paginator'],
                resourceType='AWS::EC2::Instance',
                includeDeletedResources=False
            )

        elif aws['QueryName'] == 'ebs_volume_snap':
            # Adding argument to paginator
            resources = paginate(client, aws['Paginator'], OwnerIds=[aws['AccountId']])

        elif aws['QueryName'] == 'ami':
            # Adding argument to paginator
            resources = paginate(client, aws['Paginator'], Owners=[aws['AccountId']])

        elif aws['QueryName'] == 'iam_sso_group':
            # Add argument to paginator
            resources = paginate(client, aws['Paginator'], IdentityStoreId=config.IDENTITY_STORE_ID)

        elif aws['QueryName'] == 'iam_sso_permission_sets':
            # Add argument to paginator
            permission_sets = paginate(
                client, aws['Paginator'],
                InstanceArn=config.SSO_INSTANCE_ARN
            )
            resources = get_permission_set_details(client, permission_sets)

        elif aws['QueryName'] == 'health':
            # Adding argument to paginator
            event_filters = {
                'eventTypeCategories': ['scheduledChange'],
                'eventStatusCodes': ['open', 'upcoming']
            }
            # Adding values to the response
            for event in paginate(client, aws['Paginator'], filter=event_filters):
                entity_filter = {
                    'eventArns': [event['arn']]
                }
                entity = client.describe_affected_entities(filter=entity_filter)
                for e in entity['entities']:
                    event['CustomEntityValue'] = e['entityValue']

                resources.append(event)

        elif aws['QueryName'] == 'iam_sso_account_assignments':
            aws_accounts = get_active_accounts()
            for a in aws_accounts:
                # Add argument to paginator
                permission_sets = paginate(
                    client,
                    'list_permission_sets_provisioned_to_account',
                    InstanceArn=config.SSO_INSTANCE_ARN,
                    AccountId=a['AccountId']
                )

                id_store = get_boto3_client(aws['AccountId'], 'identitystore', region=aws['Region'])

                for p in permission_sets:
                    response = paginate(
                        client,
                        aws['Paginator'],
                        InstanceArn=config.SSO_INSTANCE_ARN,
                        AccountId=a['AccountId'],
                        PermissionSetArn=p
                    )
                    for mapping in response:
                        mapping['CustomAccountAlias'] = a['AccountAlias']
                        ps = get_permission_set_detail(client, p)
                        mapping['CustomPermissionSetName'] = ps['Name']
                        if mapping['PrincipalType'] == 'GROUP':
                            grp = id_store.describe_group(
                                IdentityStoreId=config.IDENTITY_STORE_ID,
                                GroupId=mapping['PrincipalId']
                            )
                            mapping['CustomPrincipalName'] = grp['DisplayName']
                        else:
                            usr = id_store.describe_user(
                                IdentityStoreId=config.IDENTITY_STORE_ID,
                                UserId=mapping['PrincipalId']
                            )
                            mapping['CustomPrincipalName'] = usr['UserName']

                        resources.append(mapping)

        elif aws['QueryName'] == 'iam_sso_user':
            sso_groups = list(paginate(client, 'list_groups', IdentityStoreId=config.IDENTITY_STORE_ID))
            resources = list()
            for user in paginate(client, aws['Paginator'], IdentityStoreId=config.IDENTITY_STORE_ID):
                group_ids = list()
                for group_id in paginate(client, 'list_group_memberships_for_member', IdentityStoreId=config.IDENTITY_STORE_ID, MemberId={'UserId': user['UserId']}):
                    sso_group = get_dic_item(sso_groups, 'GroupId', group_id['GroupId'])
                    group_ids.append(sso_group['DisplayName'])

                user['CustomGroupIds'] = group_ids
                user['CustomLocation'] = get_user_location(user)

                resources.append(user)

        elif aws['QueryName'] == 'iam_user':
            resource = get_boto3_resource(aws['AccountId'], 'iam')
            for r in paginate(client, aws['Paginator']):
                user = resource.User(r['UserName'])

                # Check Access Keys status
                accesss_key_1 = status_key_1 = days_since_creation_key_1 = last_used_key_1 = None
                accesss_key_2 = status_key_2 = days_since_creation_key_2 = last_used_key_2 = None

                access_keys = list(paginate(client, 'list_access_keys', UserName=r['UserName']))

                for k in access_keys:   # access_keys can have from none to 2 items
                    if access_keys.index(k) == 0:
                        accesss_key_1, status_key_1, days_since_creation_key_1, \
                        last_used_key_1 = get_access_key(k, client)
                    else:
                        accesss_key_2, status_key_2, days_since_creation_key_2, \
                        last_used_key_2 = get_access_key(k, client)

                # Grab User Policies: Inline
                user_policies = list()
                inline_policies = client.list_user_policies(UserName=r['UserName'])
                if inline_policies['PolicyNames']:
                    user_policies = inline_policies['PolicyNames']

                # Grab User Policies: Atttached
                attached_policies = client.list_attached_user_policies(UserName=r['UserName'])
                for pol in attached_policies['AttachedPolicies']:
                    user_policies.append(pol['PolicyName'])

                # Grab the IAM groups attached to this user
                user_grp = list()
                user_groups = client.list_groups_for_user(UserName=r['UserName'])

                # Loop through IAM groups associated with the IAM user
                for grp in user_groups['Groups']:
                    user_grp.append(grp['GroupName'])

                    # Grab the IAM Policies associated which each group: Inline and Managed
                    inline_grp_policies = client.list_group_policies(GroupName=grp['GroupName'])
                    for policy in inline_grp_policies['PolicyNames']:
                        user_policies.append(policy)

                    # Managed policies
                    for policy in paginate(client, 'list_attached_group_policies', GroupName=grp['GroupName']):
                        user_policies.append(policy['PolicyName'])

                # Add extra values to paginator output
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
                except: # pylint: disable=broad-except
                    r['Tags'] = None

                resources.append(r)

        elif aws['QueryName'] == 'tag_editor':
            # Adding ARN splited values to paginator output
            resources = get_arn_resources(paginate(client, aws['Paginator']), 'ResourceARN')

        elif aws['QueryName'] == 'aws_backup':
            # Adding ARN splited values to paginator output
            resources = get_arn_resources(paginate(client, aws['Paginator']), 'ResourceArn')

        elif aws['QueryName'] == 'tgw_attach':
            ec2r = get_boto3_resource(aws['AccountId'], aws['Boto3Client'], region=aws['Region'])
            # Adding extra value to paginator output
            for r in paginate(client, aws['Paginator']):
                r['CustomSubnets'] = get_tgw_att_subnets(r, client, ec2r)
                resources.append(r)

        elif aws['QueryName'] == 'igw':
            # Adding extra values to paginator output
            for i in paginate(client, aws['Paginator']):
                for attach in i['Attachments']:
                    i['CustomState'] = attach['State']
                    i['CustomVpcId'] = attach['VpcId']

                resources.append(i)

        elif aws['QueryName'] == 'vpc_dhcp':
            for i in paginate(client, aws['Paginator']):
                i['CustomDnsDomains'] = get_dhcp_config(i['DhcpConfigurations'], 'domain-name')
                i['CustomDnsServers'] = get_dhcp_config(i['DhcpConfigurations'], 'domain-name-servers')
                i['CustomNtpServers'] = get_dhcp_config(i['DhcpConfigurations'], 'ntp-servers')

                resources.append(i)

        elif aws['QueryName'] == 'route_table':
            for i in paginate(client, aws['Paginator']):
                # Propagative value
                propagative_vgw = try_get_value(i, 'PropagatingVgws')
                if propagative_vgw != 'NoValue':
                    try:
                        propagative_vgw_id = propagative_vgw[0]['GatewayId']
                    except: # pylint: disable=broad-except
                        propagative_vgw_id = ''

                # List subnet/gateway associated with the route table
                associations = ''
                for a in i['Associations']:
                    associations += f"{a['AssociationState']['State']};{a['Main']};{try_get_value(a, 'SubnetId')};{try_get_value(a, 'GatewayId')}\n"

                i['CustomPropagativeVgwId'] = propagative_vgw_id
                i['CustomCountAssociations'] = len(i['Associations'])
                i['CustomAssociations'] = associations
                i['CustomCountRoutes'] = len(i['Routes'])
                i['CustomRoutes'] = get_routes(i['Routes'])

                resources.append(i)
        else:
            resources = paginate(client, aws['Paginator'])
    else:
        boto3_method = getattr(client, SETUP[config.QUERY]['Method'])

        if aws['QueryName'] == 's3_bucket':
            response = boto3_method()
            resource = get_boto3_resource(aws['AccountId'], 's3')
            for b in response[SETUP[config.QUERY]['ResponseItem']]:
                b['CreationDate'] = b['CreationDate'].strftime('%c')
                tags = resource.BucketTagging(b['Name'])
                try:
                    b['Tags'] = tags.tag_set
                except: # pylint: disable=broad-except
                    b['Tags'] = None

                resources.append(b)

        elif aws['QueryName'] == 'ram':
            response = boto3_method(resourceOwner='SELF', resourceRegionScope='REGIONAL')
            resources = get_arn_resources(response[SETUP[config.QUERY]['ResponseItem']], 'arn')

        else:
            response = boto3_method()
            resources = response[SETUP[config.QUERY]['ResponseItem']]

    return resources
