# -*- coding: utf-8 -*-
"""Helper functions for Looper class."""

from logging            import getLogger
from classes.cw_metric  import CwMetric
from helpers            import SETUP
from helpers.boto3_func import *
import helpers.config   as     config

LOGGER = getLogger(__name__)


def get_resources(aws: dict, query: str) -> list:
    """Get the fields of interest in a list of dictionaries."""

    paginator = SETUP[query]['Paginator']

    # Get main boto3 object per query and region
    service = SETUP[query]['Client']
    client = b3_client(aws['AccountId'], service, region=aws['Region'])

    # Make up queries to include values not included in the paginator response
    # or return paginator output as it is
    if paginator:
        if query == 'ec2':
            ec2_filter = [{
                'Name': 'instance-state-name',
                'Values': ['pending', 'running', 'stopping', 'stopped']
            }]
            resources = paginate_ec2(aws, client, paginator, Filters=ec2_filter)

        elif query == 'ebs_volume_snap':
            resources = paginate(client, paginator, OwnerIds=[aws['AccountId']])

        elif query == 'ami':
            resources = paginate(client, paginator, Owners=[aws['AccountId']])

        elif query == 'elb':
            resources = paginate_elb(client, paginator)

        elif query == 'elb_v2':
            resources = paginate_elb_v2(client, paginator)

        elif query == 'ssm_patching':
            resources = paginate_ssm_patching(client, paginator)

        elif query == 'rds':
            resources = paginate_rds(client, paginator)

        elif query == 'dynamodb':
            resources = paginate_dynamodb(aws, client, paginator)

        elif query == 'aws_backup':
            resources = get_arn_resources(paginate(client, paginator), 'ResourceArn')

        elif query == 'tag_editor':
            resources = get_arn_resources(paginate(client, paginator), 'ResourceARN')

        elif query == 'aws_config':
            resources = paginate(client, paginator, resourceType='AWS::EC2::Instance', includeDeletedResources=False)

        elif query == 'health':
            event_filters = {
                'eventTypeCategories': ['scheduledChange'],
                'eventStatusCodes': ['open', 'upcoming']
            }
            resources = paginate_health(client, paginator, filter=event_filters)

        elif query == 'tgw_attach':
            resources = paginate_tgw_attach(aws, client, paginator)

        elif query == 'igw':
            resources = paginate_igw(client, paginator)

        elif query == 'vpc_dhcp':
            resources = paginate_vpc_dhcp(client, paginator)

        elif query == 'route_table':
            resources = paginate_route_table(client, paginator)

        elif query == 'iam_user':
            resources = paginate_iam_user(aws, client, paginator)

        elif query == 'iam_sso_user':
            resources = paginate_iam_sso_user(client, paginator, IdentityStoreId=config.IDENTITY_STORE_ID)

        elif query == 'iam_sso_group':
            resources = paginate(client, paginator, IdentityStoreId=config.IDENTITY_STORE_ID)

        elif query == 'iam_sso_permission_sets':
            permission_sets = paginate(client, paginator, InstanceArn=config.SSO_INSTANCE_ARN)
            resources = get_permission_set_details(client, permission_sets)

        elif query == 'iam_sso_account_assignments':
            resources = paginate_iam_sso_account_assignments(aws, client, paginator)

        else:
            resources = paginate(client, paginator)
    else:
        boto3_method = getattr(client, SETUP[query]['Method'])

        if query == 's3_bucket':
            resources = s3_bucket_query(aws, query, boto3_method)
        elif query == 'ram':
            response = boto3_method(resourceOwner='SELF', resourceRegionScope='REGIONAL')
            resources = get_arn_resources(response[SETUP[query]['ResponseItem']], 'arn')
        else:
            response = boto3_method()
            resources = response[SETUP[query]['ResponseItem']]

    return resources


def s3_bucket_query(aws: dict, query: str, boto3_method: object) -> list:
    """Run S3 bucket query."""
    s3 = b3_resource(aws['AccountId'], 's3')
    cw = b3_client(aws['AccountId'], 'cloudwatch')
    cw_metric = CwMetric(cw)
    response = boto3_method()
    for b in response[SETUP[query]['ResponseItem']]:
        b['CreationDate'] = b['CreationDate'].strftime('%c')
        metric = cw_metric.get_bucket_size(b['Name'])
        b['CustomSizeGB'] = byte_to_gb(metric['Value'])
        metric = cw_metric.get_bucket_object_count(b['Name'])
        b['CustomObjectCount'] = metric['Value']
        tags = s3.BucketTagging(b['Name'])
        b['Tags'] = get_s3_tags(tags)

        yield(b)


def paginate_ec2(aws: dict, client: object, method: str, **kwargs) -> list:
    """Paginate ec2 resources and add extra values."""
    paginator = client.get_paginator(method)

    # Set boto3 client for other services required in this query
    bkp = b3_client(aws['AccountId'], 'backup', region=aws['Region'])
    ssm = b3_client(aws['AccountId'], 'ssm', region=aws['Region'])

    # Get list of instances enrolled for other services
    bkp_ena_ids   = list(get_backup_enabled_resources(bkp))
    patch_ena_ids = list(get_patching_enabled_resources(ssm))
    ssm_inventory = list(get_ssm_ec2_ids_inventory(ssm))

    for page in paginator.paginate(**kwargs).result_key_iters():
        for result in page:
            for r in result['Instances']:
                r['IsAwsBuckupEnabled'] = bool(r['InstanceId'] in bkp_ena_ids)
                r['IsSsmPatchEnabled'] = bool(r['InstanceId'] in patch_ena_ids)
                r['IsSsmAgentEnabled'] = bool(r['InstanceId'] in ssm_inventory)
                r['VolumeCount'], r['VolumeSize'] = get_volume(client, r['BlockDeviceMappings'])
                r['Platform'] = get_ec2_platform(r, 'Platform')
                r['IamInstanceProfile'] = get_ec2_instance_profile(r, 'IamInstanceProfile')

                yield r


def paginate_dynamodb(aws: dict, client: object, method: str) -> list:
    """Paginate rds instances and change tag key name."""
    paginator = client.get_paginator(method)

    for page in paginator.paginate().result_key_iters():
        for r in page:
            r['CustomTableName'] = r
            r['Tags'] = client.list_tags_of_resource(
                ResourceArn=f"arn:dynamodb:{aws['Region']}:{aws['AccountId']}:table/{r}"
            )
            yield r


def paginate_rds(client: object, method: str) -> list:
    """Paginate dynamodb tables and add extra values."""
    paginator = client.get_paginator(method)

    for page in paginator.paginate().result_key_iters():
        for r in page:
            r['Tags'] = r['TagList']
            yield r


def paginate_elb(client: object, method: str) -> list:
    """Paginate elb and add list of registered EC2 instances."""
    paginator = client.get_paginator(method)

    for page in paginator.paginate().result_key_iters():
        for r in page:
            instances = list()
            for i in r['Instances']:
                instances.append(i['InstanceId'])

            r['CustomInstances'] = " | ".join(x for x in instances)
            yield r


def paginate_elb_v2(client: object, method: str) -> list:
    """Paginate elb_v2 and add extra values."""
    paginator = client.get_paginator(method)

    for page in paginator.paginate().result_key_iters():
        for r in page:
            target_groups = list()
            for tg in paginate(client, 'describe_target_groups', LoadBalancerArn=r['LoadBalancerArn']):
                target_groups.append(f"{tg['TargetGroupName']}_({tg['TargetType']})\n")
                tg_health = client.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                targets = list()
                for t in tg_health['TargetHealthDescriptions']:
                    targets.append(f"{t['Target']['Id']}_({t['TargetHealth']['State']})\n")

            r['CustomTargetGroups'] = "".join(x for x in target_groups)
            r['CustomTargets'] = "".join(x for x in targets)
            yield r


def paginate_health(client: object, method: str, **kwargs) -> list:
    """Paginate AWS Health Dashboard and add extra values."""
    paginator = client.get_paginator(method)

    for page in paginator.paginate(**kwargs).result_key_iters():
        for event in page:
            entity_filter = {'eventArns': [event['arn']]}
            entity = client.describe_affected_entities(filter=entity_filter)
            for e in entity['entities']:
                event['CustomEntityValue'] = e['entityValue']

            yield event


def paginate_tgw_attach(aws: dict, client: object, method: str) -> list:
    """Paginate TGW attachments and add extra values."""
    ec2r = b3_resource(aws['AccountId'], 'ec2', region=aws['Region'])
    paginator = client.get_paginator(method)

    for page in paginator.paginate().result_key_iters():
        for r in page:
            r['CustomSubnets'] = get_tgw_att_subnets(r, client, ec2r)
            yield r


def paginate_igw(client: object, method: str) -> list:
    """Paginate IGW and add extra values."""
    paginator = client.get_paginator(method)

    for page in paginator.paginate().result_key_iters():
        for r in page:
            for attach in r['Attachments']:
                r['CustomState'] = attach['State']
                r['CustomVpcId'] = attach['VpcId']

            yield r


def paginate_vpc_dhcp(client: object, method: str) -> list:
    """Paginate VPC DHCP options and add extra values."""
    paginator = client.get_paginator(method)

    for page in paginator.paginate().result_key_iters():
        for r in page:
            r['CustomDnsDomains'] = get_dhcp_config(r['DhcpConfigurations'], 'domain-name')
            r['CustomDnsServers'] = get_dhcp_config(r['DhcpConfigurations'], 'domain-name-servers')
            r['CustomNtpServers'] = get_dhcp_config(r['DhcpConfigurations'], 'ntp-servers')

            yield r


def paginate_route_table(client: object, method: str) -> list:
    """Paginate VPC Route Tables options and add extra values."""
    paginator = client.get_paginator(method)

    for page in paginator.paginate().result_key_iters():
        for i in page:
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

            yield i


def paginate_ssm_patching(client: object, method: str) -> list:
    """Paginate ssm patching resources and add extra values."""

    # Fetch all instances registered with SSM service
    ssm_inventory = list(paginate(client, 'describe_instance_information'))

    paginator = client.get_paginator(method)

    for pg in paginate(client, 'describe_patch_groups'):
        for page in paginator.paginate(PatchGroup=pg['PatchGroup']).result_key_iters():
            for i in page:
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
                    yield i


def paginate_iam_user(aws: dict, client: object, method: str) -> list:
    """Paginate IAM Users and add extra values."""
    resource = b3_resource(aws['AccountId'], 'iam')

    paginator = client.get_paginator(method)
    for page in paginator.paginate().result_key_iters():
        for r in page:
            user = resource.User(r['UserName'])

            # Check Access Keys status
            r['accesss_key_1'] = r['status_key_1'] = r['days_since_creation_key_1'] = r['last_used_key_1'] = None
            r['accesss_key_2'] = r['status_key_2'] = r['days_since_creation_key_2'] = r['last_used_key_2'] = None
            access_keys = list(paginate(client, 'list_access_keys', UserName=r['UserName']))
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


def paginate_iam_sso_user(client: object, method: str, **kwargs) -> list:
    """Paginate IAM SSO Users and add extra values."""
    sso_groups = list(paginate(client, 'list_groups', **kwargs))

    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs).result_key_iters():
        for user in page:
            group_ids = list()
            for group_id in paginate(client, 'list_group_memberships_for_member', IdentityStoreId=config.IDENTITY_STORE_ID, MemberId={'UserId': user['UserId']}):
                sso_group = get_dic_item(sso_groups, 'GroupId', group_id['GroupId'])
                group_ids.append(sso_group['DisplayName'])

            user['CustomGroupIds'] = group_ids
            user['CustomLocation'] = get_user_location(user)

            yield user


def paginate_iam_sso_account_assignments(aws: dict, client: object, method: str) -> list:
    """Paginate IAM SSO Account Assignments and add extra values."""
    aws_accounts = get_active_accounts()
    for a in aws_accounts:
        # Add argument to paginator
        permission_sets = paginate(
            client,
            'list_permission_sets_provisioned_to_account',
            InstanceArn=config.SSO_INSTANCE_ARN,
            AccountId=a['AccountId']
        )

        id_store = b3_client(aws['AccountId'], 'identitystore', region=aws['Region'])

        for p in permission_sets:
            response = paginate(
                client,
                method,
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

                yield mapping
