# -*- coding: utf-8 -*-
"""Helpers functions module."""

import logging
from helpers import config

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=logging.INFO
)

LOGGER = logging.getLogger(__name__)
LOGGER.info("Initialize query settings.")

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
            'NetworkInterfaces',
            'SecurityGroups',
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
    'fsx': {
        'Client': 'fsx',
        'Paginator': 'describe_file_systems',
        'Headers': [
            'FileSystemId',
            'CreationTime',
            'DaysSince:CreationTime',
            'FileSystemType',
            'StorageCapacity',
            'StorageType',
            'WindowsConfiguration:ActiveDirectoryId'
        ]
    },
    'eni': {
        'Client': 'ec2',
        'Paginator': "describe_network_interfaces",
        'Headers': [
            'Association:AssociationId',
            'Association:PublicIp',
            'Association:PublicDnsName',
            'Attachment:AttachmentId',
            'Attachment:InstanceId',
            'Attachment:Status',
            'AvailabilityZone',
            'InterfaceType',
            'Description',
            'NetworkInterfaceId',
            'PrivateDnsName',
            'PrivateIpAddress',
            'Status',
            'SubnetId',
            'VpcId'
        ]
    },
    'elb': {
        'Client': 'elb',
        'Paginator': 'describe_load_balancers',
        'Headers': [
            'LoadBalancerName',
            'DNSName',
            'Scheme',
            'VPCId',
            'CustomInstances'
        ]
    },
    'elb_v2': {
        'Client': 'elbv2',
        'Paginator': 'describe_load_balancers',
        'Headers': [
            'LoadBalancerName',
            'DNSName',
            'Scheme',
            'Type',
            'CustomTargetGroups',
            'CustomTargets'
        ]
    },
    'ssm_inventory': {
        'Client': 'ssm',
        'Paginator': 'describe_instance_information',
        'Headers':[
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
        'Headers':[
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
    's3_bucket': {
        'Client': 's3',
        'Region': [config.REGION],
        'Paginator': None,
        'Method': 'list_buckets',
        'ResponseItem': 'Buckets',
        'Headers':[
            'Name',
            'DaysSince:CreationDate',
            'CreationDate',
            'CustomSizeGB',
            'CustomObjectCount'
        ]
    },
    'rds': {
        'Client': 'rds',
        'Paginator': 'describe_db_instances',
        'Headers': [
            'DBInstanceIdentifier',
            'DBClusterIdentifier',
            'DBName',
            'MasterUsername',
            'DBInstanceStatus',
            'DBInstanceClass',
            'AllocatedStorage',
            'Engine',
            'EngineVersion',
            'MultiAZ',
            'BackupRetentionPeriod',
            'InstanceCreateTime',
            'DaysSince:InstanceCreateTime'
        ]
    },
    'dynamodb': {
        'Client': 'dynamodb',
        'Paginator': 'list_tables',
        'Headers': [
            'CustomTableName'
        ]
    },
    'vpc': {
        'Client': 'ec2',
        'Paginator': 'describe_vpcs',
        'Headers': [
            'VpcId',
            'OwnerId',
            'CidrBlock',
            'CustomCidrBlocks',
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
    'tgw_attach': {
        'Client': 'ec2',
        'Paginator': 'describe_transit_gateway_attachments',
        'Headers': [
            'TransitGatewayAttachmentId',
            'State',
            'Association:State',
            'TransitGatewayId',
            'Association:TransitGatewayRouteTableId',
            'ResourceOwnerId',
            'ResourceType',
            'ResourceId',
            'CustomSubnets'
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
    'dx_connections': {
        'Client': 'directconnect',
        'Paginator': None,
        'Method': 'describe_connections',
        'ResponseItem': 'connections',
        'Headers': [
            'ownerAccount',
            'connectionId',
            'connectionName',
            'connectionState',
            'bandwidth',
            'location',
            'partnerName',
            'providerName'
        ]
    },
    'dx_gateway': {
        'Client': 'directconnect',
        'Paginator': None,
        'Method': 'describe_direct_connect_gateways',
        'ResponseItem': 'directConnectGateways',
        'Headers': [
            'directConnectGatewayId',
            'directConnectGatewayName',
            'amazonSideAsn',
            'ownerAccount',
            'directConnectGatewayState'
        ]
    },
    'dx_gateway_attach': {
        'Client': 'directconnect',
        'Paginator': None,
        'Method': 'describe_direct_connect_gateway_attachments',
        'ResponseItem': 'directConnectGatewayAttachments',
        'Headers': [
            'directConnectGatewayId',
            'virtualInterfaceId',
            'virtualInterfaceRegion',
            'virtualInterfaceOwnerAccount',
            'attachmentState',
            'attachmentType'
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
    'cfn_stack': {
        'Client': 'cloudformation',
        'Paginator': 'list_stacks',
        'Headers':[
            'StackId',
            'StackName',
            'TemplateDescription',
            'CreationTime',
            'LastUpdatedTime',
            'StackStatus',
            'DriftInformation:StackDriftStatus'
        ]
    },
    'cfn_stack_set': {
        'Client': 'cloudformation',
        'Paginator': 'list_stack_sets',
        'Headers':[
            'StackSetId',
            'StackSetName',
            'Description',
            'Status',
            'DriftStatus',
            'PermissionModel'
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
    'aws_config': {
        'Client': 'config',
        'Paginator': 'list_discovered_resources',
        'Headers':[
            'resourceType',
            'resourceId',
            'resourceName'
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
    'storage_gw': {
        'Client': 'storagegateway',
        'Paginator': 'list_gateways',
        'Headers':[
            'GatewayId',
            'GatewayName',
            'GatewayType',
            'Ec2InstanceId',
            'HostEnvironment',
            'HostEnvironmentId'
        ]
    },
    'health': {
        'Client': 'health',
        'Region': ['us-east-1'],
        'Paginator': 'describe_events',
        'Headers':[
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
    'ram': {
        'Client': 'ram',
        'Paginator': None,
        'Method': 'list_resources',
        'ResponseItem': 'resources',
        'Headers':[
            'ArnService',
            'ArnType',
            'ArnId'
        ]
    },
    'iam_user': {
        'Client': 'iam',
        'Region': [config.REGION],
        'Paginator': 'list_users',
        'Headers':[
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
    'iam_roles': {
        'Client': 'iam',
        'Region': [config.REGION],
        'Paginator': 'list_roles',
        'Headers': [
            'RoleName',
            'Description',
            'Arn',
            'MaxSessionDuration',
            'CreateDate',
            'DaysSince:CreateDate'
        ]
    },
    'iam_sso_user': {                           # Only works in org root account
        'Client': 'identitystore',
        'Region': [config.REGION],
        'Paginator': 'list_users',
        'Headers':[
            'UserName',
            'UserId',
            'CustomGroupIds',
            'DisplayName',
            'Title',
            'CustomLocation'
        ]
    },
    'iam_sso_group': {
        'Client': 'identitystore',
        'Region': [config.REGION],
        'Paginator': 'list_groups',
        'Headers':[
            'GroupId',
            'DisplayName',
            'Description',
            'CustomMembers'
        ]
    },
    'iam_sso_permission_sets': {
        'Client': 'sso-admin',
        'Region': [config.REGION],
        'Paginator': 'list_permission_sets',
        'Headers':[
            'Name',
            'Description',
            'SessionDuration',
            'PermissionSetArn'
        ]
    },
    'iam_sso_account_assignments': {            # Only works in org root account
        'Client': 'sso-admin',
        'Region': [config.REGION],
        'Paginator': 'list_account_assignments',
        'Headers':[
            'AccountId',
            'CustomAccountAlias',
            'PermissionSetArn',
            'CustomPermissionSetName',
            'PrincipalType',
            'PrincipalId',
            'CustomPrincipalName'
        ]
    }
}
