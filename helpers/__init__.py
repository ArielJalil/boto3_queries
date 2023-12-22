# -*- coding: utf-8 -*-
"""Helper modules."""

import logging
from helpers import config

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=logging.INFO
)

LOGGER = logging.getLogger(__name__)

# Setup for each query
SETUP = {
    'ec2': {
        'Client': 'ec2',
        'Paginator': 'describe_instances',
        'Headers': [
            'InstanceId',
            'ImageId',
            'State:Name',
            'InstanceType',
            'KeyName',
            'LaunchTime',
            'DaysSince:LaunchTime',
            'PrivateIpAddress',
            'PublicIpAddress',
            'VpcId',
            'SubnetId',
            'Architecture',
            'VolumeCount',
            'VolumeSize',
            'Platform',
            'IamInstanceProfile',
            'IsAwsBuckupEnabled',
            'IsSsmPatchEnabled',
            'IsSsmAgentEnabled'
        ]
    },
    'tag_editor': {
        'Client': 'resourcegroupstaggingapi',
        'Paginator': 'get_resources',
        'Headers': [
            'ArnService',
            'ArnType',
            'ArnId'
        ]
    },
    'ami': {
        'Client': 'ec2',
        'Paginator': 'describe_images',
        'Headers': [
            'ImageId',
            'Name',
            'Description',
            'Architecture',
            'CreationDate',
            'Public',
            'PlatformDetails'
        ]
    },
    'vpc': {
        'Client': 'ec2',
        'Paginator': 'describe_vpcs',
        'Headers': [
            'VpcId',
            'OwnerId',
            'CidrBlock',
            'DhcpOptionsId',
            'IsDefault'
        ]
    },
    'vpc_flow_logs': {
        'Client': 'ec2',
        'Paginator': 'describe_flow_logs',
        'Headers': [
            'FlowLogId',
            'FlowLogStatus',
            'ResourceId',
            'LogGroupName',
            'LogDestinationType',
            'LogDestination'
        ]
    },
    'subnet': {
        'Client': 'ec2',
        'Paginator': 'describe_subnets',
        'Headers': [
            'SubnetId',
            'VpcId',
            'OwnerId',
            'CidrBlock'
        ]
    },
    'sec_group': {
        'Client': 'ec2',
        'Paginator': 'describe_security_groups',
        'Headers': [
            'GroupId',
            'GroupName',
            'IpPermissions',
            'IpPermissionsEgress'
        ]
    },
    'vpce': {
        'Client': 'ec2',
        'Paginator': 'describe_vpc_endpoints',
        'Headers': [
            'ServiceName',
            'VpcEndpointId',
            'VpcEndpointType',
            'VpcId',
            'State',
            'PrivateDnsEnabled',
            'OwnerId'
        ]
    },
    'vpc_peering': {
        'Client': 'ec2',
        'Paginator': 'describe_vpc_peering_connections',
        'Headers': [
            'VpcPeeringConnectionId',
            'Status:Code',
            'AccepterVpcInfo:OwnerId',
            'AccepterVpcInfo:VpcId',
            'AccepterVpcInfo:Region',
            'AccepterVpcInfo:PeeringOptions:AllowDnsResolutionFromRemoteVpc',
            'RequesterVpcInfo:OwnerId',
            'RequesterVpcInfo:VpcId',
            'RequesterVpcInfo:Region',
            'RequesterVpcInfo:PeeringOptions:AllowDnsResolutionFromRemoteVpc'
        ]
    },
    'vpc_dhcp': {
        'Client': 'ec2',
        'Paginator': 'describe_dhcp_options',
        'Headers': [
            'DhcpOptionsId',
            'OwnerId',
            'CustomDnsDomains',
            'CustomDnsServers',
            'CustomNtpServers'
        ]
    },
    'tgw': {
        'Client': 'ec2',
        'Paginator': 'describe_transit_gateways',
        'Headers': [
            'TransitGatewayId',
            'OwnerId',
            'State',
            'Options:AssociationDefaultRouteTableId',
            'Options:DnsSupport',
            'Options:VpnEcmpSupport'
        ]
    },
    'tgw_attach': {
        'Client': 'ec2',
        'Paginator': 'describe_transit_gateway_attachments',
        'Headers': [
            'TransitGatewayAttachmentId',
            'State',
            'Association:State',
            'Association:TransitGatewayRouteTableId',
            'ResourceOwnerId',
            'ResourceType',
            'ResourceId',
            'CustomSubnets'
        ]
    },
    'igw': {
        'Client': 'ec2',
        'Paginator': 'describe_internet_gateways',
        'Headers': [
            'InternetGatewayId',
            'OwnerId',
            'CustomState',
            'CustomVpcId'
        ]
    },
    'nat_gw': {
        'Client': 'ec2',
        'Paginator': 'describe_nat_gateways',
        'Headers': [
            'NatGatewayId',
            'ConnectivityType',
            'State',
            'VpcId',
            'SubnetId'
        ]
    },
    'ebs_volume': {
        'Client': 'ec2',
        'Paginator': 'describe_volumes',
        'Headers': [
            'VolumeId',
            'State',
            'Size'
        ]
    },
    'ebs_volume_snap': {
        'Client': 'ec2',
        'Paginator': "describe_snapshots",
        'Headers': [
            'SnapshotId',
            'Description',
            'VolumeId',
            'VolumeSize',
            'StartTime',
            'DaysSince:StartTime'
        ]
    },
    'route_table': {
        'Client': 'ec2',
        'Paginator': 'describe_route_tables',
        'Headers': [
            'RouteTableId',
            'VpcId',
            'OwnerId',
            'CustomPropagativeVgwId',
            'CustomCountAssociations',
            'CustomAssociations',
            'CustomCountRoutes',
            'CustomRoutes'
        ]
    },
    'aws_backup': {
        'Client': 'backup',
        'Paginator': 'list_protected_resources',
        'Headers': [
            'ResourceType',
            'ArnId',
            'ResourceName',
            'LastBackupTime',
            'DaysSince:LastBackupTime'
        ]
    },
    'r53_hosted_zones': {
        'Client': 'route53',
        'Paginator': 'list_hosted_zones',
        'Headers': [
            'Id',
            'Name',
            'Config:Comment',
            'Config:PrivateZone',
            'ResourceRecordSetCount'
        ]
    },
    'ssm_inventory': {
        'Client': 'ssm',
        'Paginator': 'describe_instance_information',
        'Headers': [
            'InstanceId',
            'Name',
            'ComputerName',
            'PlatformName',
            'PlatformVersion',
            'AssociationStatus'
        ]
    },
    'ssm_patching': {
        'Client': 'ssm',
        'Paginator': 'describe_instance_patch_states_for_patch_group',
        'Headers': [
            'InstanceId',
            'PatchGroup',
            'CustomName',
            'CustomComputerName',
            'CustomOperatingSystem',
            'CustomPlatformVersion',
            'OperationStartTime',
            'OperationEndTime',
            'DaysSince:OperationEndTime'
        ]
    },
    'aws_config': {
        'Client': 'config',
        'Paginator': 'list_discovered_resources',
        'Headers': [
            'resourceType',
            'resourceId',
            'resourceName'
        ]
    },
    'iam_user': {
        'Client': 'iam',
        'Region': [config.REGION],
        'Paginator': 'list_users',
        'Headers': [
            'UserName',
            'PasswordLastUsed',
            'DaysSince:PasswordLastUsed',
            'accesss_key_1',
            'status_key_1',
            'days_since_creation_key_1',
            'last_used_key_1',
            'accesss_key_2',
            'status_key_2',
            'days_since_creation_key_2',
            'last_used_key_2',
            'user_grp',
            'user_policies'
        ]
    },
    'iam_sso_user': {                           # Only works in root account
        'Client': 'identitystore',
        'Region': [config.REGION],
        'Paginator': 'list_users',
        'Headers': [
            'UserName',
            'UserId',
            'CustomGroupIds',
            'DisplayName',
            'Title',
            'CustomLocation'
        ]
    },
    'iam_sso_group': {                     # It doesn't work in root account
        'Client': 'identitystore',
        'Region': [config.REGION],
        'Paginator': 'list_groups',
        'Headers': [
            'GroupId',
            'DisplayName',
            'Description'
        ]
    },
    'iam_sso_permission_sets': {                # Only works in root account
        'Client': 'sso-admin',
        'Region': [config.REGION],
        'Paginator': 'list_permission_sets',
        'Headers': [
            'Name',
            'Description',
            'SessionDuration',
            'PermissionSetArn'
        ]
    },
    'iam_sso_account_assignments': {            # Only works in root account
        'Client': 'sso-admin',
        'Region': [config.REGION],
        'Paginator': 'list_account_assignments',
        'Headers': [
            'AccountId',
            'CustomAccountAlias',
            'PermissionSetArn',
            'CustomPermissionSetName',
            'PrincipalType',
            'PrincipalId',
            'CustomPrincipalName'
        ]
    },
    'health': {
        'Client': 'health',
        'Region': [config.REGION],
        'Paginator': 'describe_events',
        'Headers': [
            'arn',
            'service',
            'eventTypeCode',
            'eventTypeCategory',
            'region',
            'startTime',
            'endTime',
            'lastUpdatedTime',
            'statusCode',
            'eventScopeCode',
            'CustomEntityValue'
        ]
    },
    's3_bucket': {
        'Client': 's3',
        'Region': [config.REGION],
        'Paginator': None,
        'Method': 'list_buckets',
        'ResponseItem': 'Buckets',
        'Headers': [
            'Name',
            'DaysSince:CreationDate',
            'CreationDate'
        ]
    },
    'ram': {
        'Client': 'ram',
        'Paginator': None,
        'Method': 'list_resources',
        'ResponseItem': 'resources',
        'Headers': [
            'ArnService',
            'ArnType',
            'ArnId'
        ]
    },
    'vpn': {
        'Client': 'ec2',
        'Paginator': None,
        'Method': 'describe_vpn_connections',
        'ResponseItem': 'VpnConnections',
        'Headers': [
            'Category',
            'Type',
            'VpnConnectionId',
            'TransitGatewayId',
            'CustomerGatewayId',
            'GatewayAssociationState'
        ]
    },
    'dx_vgw': {
        'Client': 'directconnect',
        'Paginator': None,
        'Method': 'describe_virtual_gateways',
        'ResponseItem': 'virtualGateways',
        'Headers': [
            'virtualGatewayId',
            'virtualGatewayState'
        ]
    },
    'dx_vif': {
        'Client': 'directconnect',
        'Paginator': None,
        'Method': 'describe_virtual_interfaces',
        'ResponseItem': 'virtualInterfaces',
        'Headers': [
            'virtualInterfaceType',
            'virtualInterfaceName',
            'virtualInterfaceState',
            'virtualInterfaceId',
            'vlan',
            'region',
            'ownerAccount'
        ]
    }
}
