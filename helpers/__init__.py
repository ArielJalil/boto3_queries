"""Helper modules."""

import logging
from datetime import datetime

from classes.session import AwsSession

# Customer specific variables
_cli_profile = 'your_cli_profile_name'    # AWS CLI profile that give you access to your service account
SERVICE_ACCOUNT_ID = '123456789012'       # AWS Account ID of your Organization root account
SERVICE_ROLE_NAME  = 'your_service_role'  # IAM role in target accounts i.e. AWSControlTowerExecution
REGION             = 'aws_region'         # Default region for your resources
IDENTITY_STORE_ID  = 'd-1234567890'       # Identity store ID if you are using SSO Login

MANDATORY_TAGS = {                  # Tags of interest that will be used in the query output
    'Name':              'NoValue', # Resource name
    'CostCode':          'NoValue', # Finance code used for internal billing
    'BusUnit':           'NoValue', # Department owning the resource
    'App':               'NoValue', # Application Name        bbb
    'Env':               'NoValue', # Sandbox / DEV / TEST / QA / PRE-PROD / PROD / DR
    'Priority':          'NoValue', # Incident priority the fail of this resource can generate
    'Category':          'NoValue', # Public / Private
    'ProductOwner':      'NoValue', # Resource owner team
    'ManagedBy':         'NoValue', # Support team name
    # ----- EC2 specific tags ----- #
    'ManagementType':    'NoValue', # Pet / Cattle
    'BackupType':        'NoValue', # AWS BKP / Snapshots / None
    'PatchingType':      'NoValue', # Automated / Manual
    'MaintenanceWindow': 'NoValue', # Timeframe for outage
    'IsSsmAgent':        'NoValue', # True / False
    # ----------------------------- #
    'GitRepoName':       'NoValue', # Repository name to look for IaC code
    'DeploymentType':    'NoValue'  # CFN / CDK / Terraform / Console
}

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=logging.INFO
)

LOGGER = logging.getLogger(__name__)

# Choose the AWS cli profile name and region | ap-southeast-2 by default
_session_obj = AwsSession(_cli_profile)
SESSION = _session_obj.cli()

# Date to add when creating csv output files
DATE = datetime.now().strftime("%Y%m%d-%H%M%S")

# Setup for each query
SETUP = {
    'ec2': {
        'Client': 'ec2',
        'Paginator': 'describe_instances',
        'Headers': [
            'Instance ID',
            'Image ID',
            'State',
            'Instance type',
            'Key name',
            'Launch Time',
            'Days old',
            'Private IP address',
            'Public IP address',
            'VPC ID',
            'Subnet ID',
            'Architecture',
            'EBS volume count',
            'EBS volume size (GB)',
            'Platform',
            'IAM Instance Profile ARN',
            'IsAwsBuckupEnabled',
            'IsSsmPatchEnabled',
            'IsSsmAgentEnabled'
        ]
    },
    'tag_editor': {
        'Client': 'resourcegroupstaggingapi',
        'Paginator': 'get_resources',
        'Headers': [
            'Service',
            'Resource Type',
            'Resource ID'
        ]
    },
    'vpc': {
        'Client': 'ec2',
        'Paginator': 'describe_vpcs',
        'Headers': [
            'ID',
            'Owner ID',
            'CIDR Block',
            'DHCP Options ID',
            'IsDefault'
        ]
    },
    'vpn': {
        'Client': 'ec2',
        'Paginator': None,
        'Headers': [
            'Category',
            'Name',
            'Type',
            'VPN Connection ID',
            'CGW ID',
            'TGW ID',
            'Gateway Association State'
        ]
    },
    'subnet': {
        'Client': 'ec2',
        'Paginator': 'describe_subnets',
        'Headers': [
            'Subnet ID',
            'VPC ID',
            'Owner ID',
            'CIDR Block'
        ]
    },
    'sec_group': {
        'Client': 'ec2',
        'Paginator': 'describe_security_groups',
        'Headers': [
            'Sec-Group ID',
            'Sec-Group Name'
        ]
    },
    'vpce': {
        'Client': 'ec2',
        'Paginator': 'describe_vpc_endpoints',
        'Headers': [
            'Service Name',
            'Endpoint ID',
            'Endpoint Type',
            'VPC ID',
            'State',
            'Private DNS Enabled',
            'Owner Account'
        ]
    },
    'vpc_peering': {
        'Client': 'ec2',
        'Paginator': 'describe_vpc_peering_connections',
        'Headers': [
            'ID',
            'Status',
            'Accepter Owner ID',
            'Accepter VPC ID',
            'Accepter Region',
            'Accepter Allow remote DNS resolution',
            'Requester Owner ID',
            'Requester VPC ID',
            'Requester Region',
            'Requester Allow remote DNS resolution'
        ]
    },
    'vpc_dhcp': {
        'Client': 'ec2',
        'Paginator': 'describe_dhcp_options',
        'Headers': [
            'DHCP Options ID',
            'Owner Account',
            'Domain Name',
            'Domain Name Servers'
        ]
    },
    'tgw': {
        'Client': 'ec2',
        'Paginator': 'describe_transit_gateways',
        'Headers': [
            'ID',
            'Owner ID',
            'State',
            'Association Default Route Table ID',
            'DNS Support',
            'VPN ECMP Support'
        ]
    },
    'tgw_attach': {
        'Client': 'ec2',
        'Paginator': 'describe_transit_gateway_attachments',
        'Headers': [
            'TGW Attachemnt ID',
            'State',
            'Association State',
            'TGW Route Table ID',
            'Owner ID',
            'Resource Type',
            'Resource ID',
            'Subnets'
        ]
    },
    'dx_vgw': {
        'Client': 'directconnect',
        'Paginator': None,
        'Headers': [
            'VGW ID',
            'State'
        ]
    },
    'vx_vif': {
        'Client': 'directconnect',
        'Paginator': None,
        'Headers': [
            'Type',
            'Name',
            'State',
            'VIF ID',
            'VLAN',
            'Region',
            'Owner Account'
        ]
    },
    'igw': {
        'Client': 'ec2',
        'Paginator': 'describe_internet_gateways',
        'Headers': [
            'IGW ID',
            'Owner ID',
            'Attachemnt State',
            'VPC ID'
        ]
    },
    'nat_gw': {
        'Client': 'ec2',
        'Paginator': 'describe_nat_gateways',
        'Headers': [
            'ID',
            'Connectivity Type',
            'State',
            'VPC ID',
            'Subnet Id'
        ]
    },
    'ebs_volume': {
        'Client': 'ec2',
        'Paginator': 'describe_volumes',
        'Headers': [
            'Volume ID',
            'State',
            'Size'
        ]
    },
    'ebs_volume_snap': {
        'Client': 'ec2',
        'Paginator': "describe_snapshots",
        'Headers': [
            'Snapshot ID',
            'Snapshot Description',
            'Volume ID',
            'Volume Size',
            'StartTime',
            'Days old'
        ]
    },
    'route_table': {
        'Client': 'ec2',
        'Paginator': 'describe_route_tables',
        'Headers': [
            'Route Table ID',
            'VPC ID',
            'Owner ID',
            'Propagating VGWs',
            '# Associations',
            'Associations details',
            '# Routes',
            'Route details'
        ]
    },
    'aws_backup': {
        'Client': 'backup',
        'Paginator': 'list_protected_resources',
        'Headers': [
            'Resource Type',
            'Resource ID',
            'Resource Name',
            'Last Backup date',
            'Days since last backup'
        ]
    },
    'r53_hosted_zones': {
        'Client': 'route53',
        'Paginator': 'list_hosted_zones',
        'Headers': [
            'ID',
            'Name',
            'Comment',
            'Private Zone',
            'Record Set Count'
        ]
    },
    'ssm_inventory': {
        'Client': 'ssm',
        'Paginator': 'describe_instance_information',
        'Headers':[
            'Instance ID',
            'Instance Name',
            'Computer Name',
            'Platform',
            'Platform version',
            'Association Status'
        ]
    },
    'ssm_patching': {
        'Client': 'ssm',
        'Paginator': 'describe_instance_patch_states_for_patch_group',
        'Headers':[
            'Instance ID',
            'Patch Group',
            'Operating System',
            'Operation start time',
            'Operation end time'
        ]
    },
    'aws_config': {
        'Client': 'config',
        'Paginator': 'list_discovered_resources',
        'Headers':[
            'Resource Type',
            'Resource ID',
            'Resource Name'
        ]
    },
    'ram': {
        'Client': 'ram',
        'Paginator': None,
        'Headers':[
            'Service',
            'Resource Type',
            'Resource ID'
        ]
    },
    's3_bucket': {
        'Client': 's3',
        'Region': [REGION],
        'Paginator': None,
        'Headers':[
            'S3 Bucket Name',
            'Creation Date'
        ]
    },
    'iam_user': {
        'Client': 'iam',
        'Region': [REGION],
        'Paginator': 'list_users',
        'Headers':[
            'User Name',
            'Password Last Used',
            'Days since last login',
            'accesss_key_1',
            'status_key_1',
            'Days since creation',
            'Days since last use',
            'accesss_key_2',
            'status_key_2',
            'Days since creation',
            'Days since last use',
            'IAM Groups',
            'IAM User Policies'
        ]
    },
    'iam_sso_user': {
        'Client': 'identitystore',
        'Region': [REGION],
        'Paginator': 'list_users',
        'Headers':[
            'User Name',
            'User ID',
            'Group IDs',
            'Display Name',
            'Title',
            'Street Address'
        ]
    },
    'iam_sso_group': {
        'Client': 'identitystore',
        'Region': [REGION],
        'Paginator': 'list_groups',
        'Headers':[
            'Group ID',
            'Display Name',
            'Description'
        ]
    }
}
