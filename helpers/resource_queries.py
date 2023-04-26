# -*- coding: utf-8 -*-
"""
Boto3 query.

Generate a list with the fields of interest from a boto3 paginated response.
"""
import logging

from helpers.boto3_func  import try_get_value, get_days_since, \
                                get_instance_profile, get_ec2_platform
from classes.arn_handler import ArnHandler

LOGGER = logging.getLogger(__name__)


def ec2(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return [
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
        r['VolumeCount'],
        r['VolumeSize'],
        get_ec2_platform(r, 'Platform'),
        get_instance_profile(r, 'IamInstanceProfile'),
        r['IsAwsBuckupEnabled'],
        r['IsSsmPatchEnabled'],
        r['IsSsmAgentEnabled']
    ]


def tag_editor(r:dict) -> list:
    """Gather resource details of interest in a list."""
    arn = ArnHandler(r['ResourceARN'])
    return [
        arn.service(),
        arn.resource_type(),
        arn.resource_id()
    ]


def ssm_inventory(i:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        i['InstanceId'],
        try_get_value(i, 'Name'),
        try_get_value(i, 'ComputerName'),
        i['PlatformName'],
        i['PlatformVersion'],
        try_get_value(i, 'AssociationStatus')
    ]


def ssm_patching(i:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        i['InstanceId'],
        i['PatchGroup'],
        i['OperatingSystem'],
        i['OperationStartTime'],
        i['OperationEndTime']
    ]


def aws_backup(r:dict) -> list:
    """Gather resource details of interest in a list."""
    arn = ArnHandler(r['ResourceARN'])
    return[
        r['ResourceType'],
        arn.resource_id(),
        try_get_value(r, 'ResourceName'),
        r['LastBackupTime'],
        get_days_since(r['LastBackupTime'])
    ]


def vpc(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['VpcId'],
        r['OwnerId'],
        r['CidrBlock'],
        r['DhcpOptionsId'],
        r['IsDefault']
    ]


def subnet(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['SubnetId'],
        r['VpcId'],
        r['OwnerId'],
        r['CidrBlock']
    ]


def sec_group(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['GroupId'],
        r['GroupName']
    ]


def vpce(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['ServiceName'],
        r['VpcEndpointId'],
        r['VpcEndpointType'],
        r['VpcId'],
        r['State'],
        try_get_value(r, 'PrivateDnsEnabled'),
        r['OwnerId']
    ]


def vpc_peering(r:dict) -> list:
    """Gather resource details of interest in a list."""
    try:
        accepter_dns = r['AccepterVpcInfo']['PeeringOptions']['AllowDnsResolutionFromRemoteVpc']
    except:
        accepter_dns = None

    try:
        requester_dns = r['RequesterVpcInfo']['PeeringOptions']['AllowDnsResolutionFromRemoteVpc']
    except:
        requester_dns = None

    return[
            r['VpcPeeringConnectionId'],
            r['Status']['Code'],
            r['AccepterVpcInfo']['OwnerId'],
            r['AccepterVpcInfo']['VpcId'],
            r['AccepterVpcInfo']['Region'],
            accepter_dns,
            r['RequesterVpcInfo']['OwnerId'],
            r['RequesterVpcInfo']['VpcId'],
            r['RequesterVpcInfo']['Region'],
            requester_dns,
    ]


def vpc_dhcp(r:dict) -> list:
    """Gather resource details of interest in a list."""
    columns = [
        r['DhcpOptionsId'],
        r['OwnerId']
    ]

    for option in r['DhcpConfigurations']:
        values = []
        for value in option['Values']:
            values.append(value['Value'])

        columns += [' '.join(values)]

    return columns


def vpn(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['Category'],
        r['Tags'][0]['Value'],
        r['Type'],
        r['VpnConnectionId'],
        try_get_value(r, 'TransitGatewayId'),
        r['CustomerGatewayId'],
        r['GatewayAssociationState']
    ]


def tgw(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['TransitGatewayId'],
        r['OwnerId'],
        r['State'],
        r['Options']['AssociationDefaultRouteTableId'],
        r['Options']['DnsSupport'],
        r['Options']['VpnEcmpSupport']
    ]


def tgw_attach(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['TransitGatewayAttachmentId'],
        r['State'],
        r['Association']['State'],
        r['Association']['TransitGatewayRouteTableId'],
        r['ResourceOwnerId'],
        r['ResourceType'],
        r['ResourceId'],
        r['Subnets']
    ]


def dx_vif(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['virtualInterfaceType'],
        r['virtualInterfaceName'],
        r['virtualInterfaceState'],
        r['virtualInterfaceId'],
        r['vlan'],
        r['region'],
        r['ownerAccount']
    ]


def dx_vgw(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['virtualGatewayId'],
        r['virtualGatewayState']
    ]


def igw(r:dict) -> list:
    """Gather resource details of interest in a list."""
    columns = [
        r['InternetGatewayId'],
        r['OwnerId']
    ]

    for attach in r['Attachments']:
        columns += [
            attach['State'],
            attach['VpcId']
        ]

    return columns


def nat_gw(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['NatGatewayId'],
        r['ConnectivityType'],
        r['State'],
        r['VpcId'],
        r['SubnetId']
    ]


def ram(r:dict) -> list:
    """Gather resource details of interest in a list."""
    arn = ArnHandler(r['arn'])
    return[
        arn.service(),
        arn.resource_type(),
        arn.resource_id()
    ]


def aws_config(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['resourceType'],
        r['resourceId'],
        try_get_value(r, 'resourceName')
    ]


def ebs_volume(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['VolumeId'],
        r['State'],
        r['Size']
    ]


def ebs_volume_snap(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['SnapshotId'],
        r['Description'],
        r['VolumeId'],
        r['VolumeSize'],
        r['StartTime'],
        get_days_since(r['StartTime'])
    ]


def s3_bucket(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['Name'],
        r['CreationDate'].strftime('%c')
    ]


def iam_user(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['UserName'],
        r['pass_last_used'],
        r['days_since_last_login'],
        r['is_api_key_allow'],
        r['accesss_key_1'],
        r['status_key_1'],
        r['days_since_creation_key_1'],
        r['last_used_key_1'],
        r['accesss_key_2'],
        r['status_key_2'],
        r['days_since_creation_key_2'],
        r['last_used_key_2'],
        r['user_grp'],
        r['user_policies']
    ]


def iam_sso_user(r:dict) -> list:
    """Gather resource details of interest in a list."""
    try:
        user_address = r['Addresses'][0]['StreetAddress']
    except:
        user_address = ''

    return[
        r['UserName'],
        r['UserId'],
        r['GroupIds'],
        r['DisplayName'],
        try_get_value(r, 'Title'),
        user_address
    ]


def iam_sso_group(r:dict) -> list:
    """Gather resource details of interest in a list."""
    return[
        r['GroupId'],
        r['DisplayName'],
        try_get_value(r, 'Description')
    ]


def r53_hosted_zones(r:dict) -> list:
    """Gather resource details of interest in a list."""
    try:
        comment = r['Config']['Comment']
    except:
        comment = ''

    return[
        r['Id'],
        r['Name'],
        comment,
        r['Config']['PrivateZone'],
        r['ResourceRecordSetCount']
    ]


def route_table(r:dict) -> list:
    """Gather resource details of interest in a list."""
    # Propagative value
    propagative_vgw = try_get_value(r, 'PropagatingVgws')
    if propagative_vgw != 'NoValue':
        propagative_vgw_id = propagative_vgw[0]['GatewayId']

    # List subnet/gateway associated with the route table
    associations = ''
    for a in r['Associations']:
        associations += f"{a['AssociationState']['State']};{a['Main']};{try_get_value(a, 'SubnetId')};{try_get_value(a, 'GatewayId')}\n"

    # List routes as a string
    routes = ''
    for x in r['Routes']:
        gateway = ''
        for key in x.keys():
            if 'Destination' in key:
                destination = x[key]

            # Targets
            if 'Id' in key:
                gateway = x[key]

        # Fix when the target is an EC2 instance (i.e. NAT Instance)
        if 'InstanceOwnerId' in x.keys():
            gateway = f"{x['InstanceId']}-({x['InstanceOwnerId']})"

        # If no target was found try Core Network ARN
        if not gateway:
            gateway = try_get_value(x, 'CoreNetworkArn')

        # Gather the routes in a variable
        routes += f"{destination};{gateway};{x['Origin']};{x['State']}\n"

    # Write CSV column row
    return [
        r['RouteTableId'],
        r['VpcId'],
        r['OwnerId'],
        propagative_vgw_id,
        len(r['Associations']),
        associations,
        len(r['Routes']),
        routes
    ]
