# -*- coding: utf-8 -*-
"""Set of functions to gather AWS resources."""

from logging import getLogger
from botocore.exceptions import ClientError
from classes.python_sdk import Paginator, AwsPythonSdk
from classes.python_arrays import GetItemFrom
from helpers import config, SETUP
from helpers.boto3_func import get_permission_set_details, get_permission_set_detail, \
                               get_ec2_platform, get_dx_gw_attach, get_dhcp_config, get_volume, \
                               get_iam_usr_groups, get_arn_resources, get_operating_system, \
                               get_patching_enabled_resources, get_access_key, get_routes, \
                               get_ec2_sec_grps, get_tgw_att_subnets, s3_bucket_query, \
                               get_user_location, get_backup_enabled_resources, get_user_tags, \
                               get_ec2_instance_profile, try_get_value, get_iam_usr_policies

LOGGER = getLogger(__name__)


def get_resources(aws: dict, query: str) -> list:  # pylint: disable=R0912,R0915
    """Get the fields of interest in a list of dictionaries."""

    # Get main boto3 objects per query and region
    service = SETUP[query]['Client']
    client = AwsPythonSdk(aws['AccountId'], service, aws['Region']).client()
    paginator_method = SETUP[query]['Paginator']

    # Make up queries to include values not included in the paginator response
    # or return paginator output as it is
    if paginator_method:
        paginator = Paginator(client, paginator_method)

        if query == 'ec2':
            ec2_filter = [{
                'Name': 'instance-state-name',
                'Values': ['pending', 'running', 'stopping', 'stopped']
            }]
            resources = paginate_ec2(aws, client, paginator.paginate(Filters=ec2_filter))

        elif query == 'ebs_volume_snap':
            resources = paginator.paginate(OwnerIds=[aws['AccountId']])

        elif query == 'ami':
            resources = paginator.paginate(Owners=[aws['AccountId']])

        elif query == 'elb':
            resources = paginate_elb(paginator.paginate())

        elif query == 'elb_v2':
            resources = paginate_elb_v2(client, paginator.paginate())

        elif query == 'ssm_patching':
            resources = paginate_ssm_patching(client, paginator)

        elif query == 'rds':
            resources = paginate_rds(paginator.paginate())

        elif query == 'dynamodb':
            resources = paginate_dynamodb(aws, client, paginator.paginate())

        elif query == 'aws_backup':
            resources = get_arn_resources(paginator.paginate(), 'ResourceArn')

        elif query == 'tag_editor':
            resources = get_arn_resources(paginator.paginate(), 'ResourceARN')

        elif query == 'aws_config':
            resources = paginator.paginate(
                resourceType='AWS::EC2::Instance',
                includeDeletedResources=False
            )

        elif query == 'health':
            event_filters = {
                'eventTypeCategories': ['scheduledChange'],
                'eventStatusCodes': ['open', 'upcoming']
            }
            resources = paginate_health(client, paginator.paginate(filter=event_filters))

        elif query == 'tgw_attach':
            resources = paginate_tgw_attach(aws, client, paginator.paginate())

        elif query == 'igw':
            resources = paginate_igw(paginator.paginate())

        elif query == 'vpc':
            resources = paginate_vpc(paginator.paginate())

        elif query == 'vpc_dhcp':
            resources = paginate_vpc_dhcp(paginator.paginate())

        elif query == 'route_table':
            resources = paginate_route_table(paginator.paginate())

        elif query == 'iam_user':
            resources = paginate_iam_user(aws, client, paginator.paginate())

        elif query == 'iam_sso_user':
            resources = paginate_iam_sso_users(
                client, paginator,
                IdentityStoreId=config.IDENTITY_STORE_ID
            )

        elif query == 'iam_sso_group':
            resources = paginate_iam_sso_groups(client, paginator)

        elif query == 'iam_sso_permission_sets':
            permission_sets = paginator.paginate(InstanceArn=config.SSO_INSTANCE_ARN)
            resources = get_permission_set_details(client, permission_sets)

        elif query == 'iam_sso_account_assignments':
            resources = paginate_iam_sso_account_assignments(aws, client, paginator)

        else:
            resources = paginator.paginate()
    else:
        boto3_method = getattr(client, SETUP[query]['Method'])

        if query == 's3_bucket':
            resources = s3_bucket_query(aws, query, boto3_method)
        elif query == 'ram':
            response = boto3_method(resourceOwner='SELF', resourceRegionScope='REGIONAL')
            resources = get_arn_resources(response[SETUP[query]['ResponseItem']], 'arn')
        elif query == 'dx_gateway_attach':
            resources = get_dx_gw_attach(query, client, boto3_method)
        else:
            response = boto3_method()
            resources = response[SETUP[query]['ResponseItem']]

    return resources


# ######################## #
#                          #
#  Specialized paginators  #
#                          #
# ######################## #


def paginate_ec2(aws: dict, client: str, paginator: object) -> any:
    """Paginate ec2 resources and add extra values."""

    # Set boto3 client for other services required in this query
    bkp = AwsPythonSdk(aws['AccountId'], 'backup', aws['Region']).client()
    ssm = AwsPythonSdk(aws['AccountId'], 'ssm', aws['Region']).client()

    # Get list of instances enrolled for other services
    bkp_ena_ids = list(get_backup_enabled_resources(bkp))
    patch_ena_ids = list(get_patching_enabled_resources(ssm))
    ssm_inventory = [
        i['InstanceId'] for i in Paginator(ssm, 'describe_instance_information').paginate()
    ]

    for i in paginator:
        for r in i['Instances']:
            r['IsAwsBuckupEnabled'] = bool(r['InstanceId'] in bkp_ena_ids)
            r['IsSsmPatchEnabled'] = bool(r['InstanceId'] in patch_ena_ids)
            r['IsSsmAgentEnabled'] = bool(r['InstanceId'] in ssm_inventory)
            r['VolumeCount'], r['VolumeSize'] = get_volume(client, r['BlockDeviceMappings'])
            r['Platform'] = get_ec2_platform(r, 'Platform')
            r['IamInstanceProfile'] = get_ec2_instance_profile(r, 'IamInstanceProfile')
            enis = r['NetworkInterfaces']
            r['NetworkInterfaces'] = [eni['NetworkInterfaceId'] for eni in enis]
            r['SecurityGroups'] = get_ec2_sec_grps(enis)
            yield r


def paginate_elb(paginator: object) -> any:
    """Paginate elb and add list of registered EC2 instances."""
    for r in paginator:
        instances = []
        for i in r['Instances']:
            instances.append(i['InstanceId'])

        r['CustomInstances'] = " | ".join(x for x in instances)
        yield r


def paginate_elb_v2(client: object, paginator: object) -> any:
    """Paginate elb_v2 and add extra values."""
    for r in paginator:
        target_groups = []
        tgs = Paginator(
            client, 'describe_target_groups'
        ).paginate(LoadBalancerArn=r['LoadBalancerArn'])
        for tg in tgs:
            target_groups.append(f"{tg['TargetGroupName']}_({tg['TargetType']})\n")
            tg_health = client.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
            targets = []
            for t in tg_health['TargetHealthDescriptions']:
                targets.append(f"{t['Target']['Id']}_({t['TargetHealth']['State']})\n")

        r['CustomTargetGroups'] = "".join(x for x in target_groups)
        r['CustomTargets'] = "".join(x for x in targets)
        yield r


def paginate_ssm_patching(client: object, paginator: object) -> any:
    """Paginate ssm patching resources and add extra values."""

    # Fetch all instances registered with SSM service
    ssm_inventory = list(Paginator(client, 'describe_instance_information').paginate())

    for pg in Paginator(client, 'describe_patch_groups').paginate():
        for i in paginator.paginate(PatchGroup=pg['PatchGroup']):
            i['CustomOperatingSystem'] = pg['BaselineIdentity']['OperatingSystem']
            vm_from_inventory = GetItemFrom(
                ssm_inventory
            ).by_key_pair('InstanceId', i['InstanceId'])
            i['CustomName'] = try_get_value(vm_from_inventory, 'Name')
            i['CustomComputerName'] = try_get_value(vm_from_inventory, 'ComputerName')
            i['CustomPlatformVersion'] = try_get_value(vm_from_inventory, 'PlatformVersion')
            platform = None
            if vm_from_inventory:
                platform = get_operating_system(vm_from_inventory['PlatformName'])
                i['CustomIsInSsmInventory'] = True
            else:
                i['CustomIsInSsmInventory'] = False

            if i['CustomOperatingSystem'] == platform and i['CustomIsInSsmInventory'] is True:
                yield i


def paginate_rds(paginator: object) -> any:
    """Paginate dynamodb tables and add extra values."""
    for r in paginator:
        r['Tags'] = r['TagList']
        yield r


def paginate_dynamodb(aws: dict, client: object, paginator: object) -> any:
    """Paginate rds instances and change tag key name."""
    for r in paginator:
        table = client.list_tags_of_resource(
            ResourceArn=f"arn:aws:dynamodb:{aws['Region']}:{aws['AccountId']}:table/{r}"
        )
        yield {
            'CustomTableName': r,
            'Tags': table['Tags']
        }


def paginate_health(client: object, paginator: object) -> any:
    """Paginate AWS Health Dashboard and add extra values."""
    for event in paginator:
        entity_filter = {'eventArns': [event['arn']]}
        entity = client.describe_affected_entities(filter=entity_filter)
        for e in entity['entities']:
            event['CustomEntityValue'] = e['entityValue']

        yield event


def paginate_tgw_attach(aws: dict, client: object, paginator: object) -> any:
    """Paginate TGW attachments and add extra values."""
    ec2r = AwsPythonSdk(aws['AccountId'], 'ec2', aws['Region']).resource()

    for r in paginator:
        r['CustomSubnets'] = get_tgw_att_subnets(r, client, ec2r)
        yield r


def paginate_igw(paginator: object) -> any:
    """Paginate IGW and add extra values."""
    for r in paginator:
        for attach in r['Attachments']:
            r['CustomState'] = attach['State']
            r['CustomVpcId'] = attach['VpcId']

        yield r


def paginate_vpc(paginator: object) -> any:
    """Paginate VPC DHCP options and add extra values."""
    for r in paginator:
        r['CustomCidrBlocks'] = []
        for c in r['CidrBlockAssociationSet']:
            r['CustomCidrBlocks'].append(c['CidrBlock'])

        yield r


def paginate_vpc_dhcp(paginator: object) -> any:
    """Paginate VPC DHCP options and add extra values."""
    for r in paginator:
        r['CustomDnsDomains'] = get_dhcp_config(r['DhcpConfigurations'], 'domain-name')
        r['CustomDnsServers'] = get_dhcp_config(r['DhcpConfigurations'], 'domain-name-servers')
        r['CustomNtpServers'] = get_dhcp_config(r['DhcpConfigurations'], 'ntp-servers')

        yield r


def paginate_route_table(paginator: object) -> any:
    """Paginate VPC Route Tables options and add extra values."""
    for i in paginator:
        propagative_vgw_id = ''
        propagative_vgw = try_get_value(i, 'PropagatingVgws')
        if propagative_vgw != 'NoValue':
            try:
                propagative_vgw_id = propagative_vgw[0]['GatewayId']
            except IndexError:
                propagative_vgw_id = ''

        # List subnet/gateway associated with the route table
        associations = ''
        for a in i['Associations']:
            associations += f"{a['AssociationState']['State']};{a['Main']};{try_get_value(a, 'SubnetId')};{try_get_value(a, 'GatewayId')}\n"  # pylint: disable=C0301

        i['CustomPropagativeVgwId'] = propagative_vgw_id
        i['CustomCountAssociations'] = len(i['Associations'])
        i['CustomAssociations'] = associations
        i['CustomCountRoutes'] = len(i['Routes'])
        i['CustomRoutes'] = get_routes(i['Routes'])

        yield i


def paginate_iam_user(aws: dict, client: object, paginator: str) -> any:
    """Paginate IAM Users and add extra values."""
    resource = AwsPythonSdk(aws['AccountId'], 'iam').resource()

    for r in paginator:
        user = resource.User(r['UserName'])

        # Check Access Keys status
        r['accesss_key_1'] = r['status_key_1'] = r['days_since_creation_key_1'] = r['last_used_key_1'] = None  # pylint: disable=C0301
        r['accesss_key_2'] = r['status_key_2'] = r['days_since_creation_key_2'] = r['last_used_key_2'] = None  # pylint: disable=C0301
        access_keys = list(Paginator(client, 'list_access_keys').paginate(UserName=r['UserName']))
        for k in access_keys:   # access_keys can have from none to 2 items
            if access_keys.index(k) == 0:
                r['accesss_key_1'], r['status_key_1'], r['days_since_creation_key_1'], \
                r['last_used_key_1'] = get_access_key(k, client)
            else:
                r['accesss_key_2'], r['status_key_2'], r['days_since_creation_key_2'], \
                r['last_used_key_2'] = get_access_key(k, client)

        # Grab User specific IAM Policies/Groups
        user_policies = get_iam_usr_policies(client, r['UserName'])
        r['user_grp'], grp_policies = get_iam_usr_groups(client, r['UserName'])
        r['user_policies'] = user_policies + grp_policies
        r['Tags'] = get_user_tags(user)

        yield r


def paginate_iam_sso_users(client: object, paginator: str, **kwargs) -> any:
    """Paginate IAM SSO Users and add extra values."""
    sso_groups = list(Paginator(client, 'list_groups').paginate(**kwargs))

    for user in paginator.paginate(**kwargs):
        group_ids = []
        for group_id in Paginator(client, 'list_group_memberships_for_member').paginate(
                IdentityStoreId=config.IDENTITY_STORE_ID,
                MemberId={'UserId': user['UserId']}):
            sso_group = GetItemFrom(sso_groups).by_key_pair('GroupId', group_id['GroupId'])
            group_ids.append(sso_group['DisplayName'])

        user['CustomGroupIds'] = group_ids
        user['CustomLocation'] = get_user_location(user)

        yield user


def paginate_iam_sso_groups(client: object, paginator: str) -> any:
    """Paginate IAM SSO Groups and add extra values."""
    iam_sso_groups = paginator.paginate(IdentityStoreId=config.IDENTITY_STORE_ID)
    for group in iam_sso_groups:
        members = Paginator(client, "list_group_memberships").paginate(
            IdentityStoreId=config.IDENTITY_STORE_ID,
            GroupId=group['GroupId']
        )
        group_members = ""
        for member in members:
            user = client.describe_user(
                IdentityStoreId=config.IDENTITY_STORE_ID,
                UserId=member['MemberId']['UserId']
            )
            group_members += user['UserName'] + " "

        group['CustomMembers'] = group_members

        yield group


def paginate_iam_sso_account_assignments(aws: dict, client: object, paginator: object) -> any:
    """Paginate IAM SSO Account Assignments and add extra values."""
    aws_accounts = AwsPythonSdk(config.ROOT_ACCOUNT_ID, 'organizations').org_accounts()
    for a in aws_accounts:
        # Add argument to paginator
        permission_sets = Paginator(client, 'list_permission_sets_provisioned_to_account').paginate(
            InstanceArn=config.SSO_INSTANCE_ARN,
            AccountId=a['AccountId']
        )

        id_store = AwsPythonSdk(aws['AccountId'], 'identitystore', aws['Region']).client()

        for p in permission_sets:
            response = paginator.paginate(
                InstanceArn=config.SSO_INSTANCE_ARN,
                AccountId=a['AccountId'],
                PermissionSetArn=p
            )
            for mapping in response:
                mapping['CustomAccountAlias'] = a['AccountAlias']
                ps = get_permission_set_detail(client, p)
                mapping['CustomPermissionSetName'] = ps['Name']

                if mapping['PrincipalType'] == 'GROUP':
                    try:
                        grp = id_store.describe_group(
                            IdentityStoreId=config.IDENTITY_STORE_ID,
                            GroupId=mapping['PrincipalId']
                        )
                        mapping['CustomPrincipalName'] = grp['DisplayName']
                    except ClientError:
                        mapping['CustomPrincipalName'] = "Group not found"
                else:
                    try:
                        usr = id_store.describe_user(
                            IdentityStoreId=config.IDENTITY_STORE_ID,
                            UserId=mapping['PrincipalId']
                        )
                        mapping['CustomPrincipalName'] = usr['UserName']

                    except ClientError:
                        mapping['CustomPrincipalName'] = 'User not found'

                yield mapping
