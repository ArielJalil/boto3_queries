# -*- coding: utf-8 -*-
"""Global variable across modules."""

# import os
import logging

LOGGER = logging.getLogger(__name__)

# Path to store query output CSV files
# CSV_PATH = '/tmp/'
CSV_PATH = 'query_output/'

# Windows user running WSL
# USER = os.getenv('USER')
# CSV_PATH = f"/mnt/c/Users/{USER}/Downloads/"

# Initialize query name to run
QUERY = None

# Initialize boto3 session
SESSION = None

# Customer specific variables
CLI_PROFILE = 'YOUR AWS CLI PROFILE'
ROOT_ACCOUNT_ID = '123456789012'
EXCLUSION_LIST = []                           # AWS account IDs to be excluded from queries
SERVICE_ACCOUNT_ID = '123456789012'           # It could be your Org root account ID
SERVICE_ROLE_NAME = 'YOUR SERVICE ROLE'       # i.e. AWSControlTowerExecution
REGION = 'ap-southeast-2'                     # Default region
IDENTITY_STORE_ID = 'YOUR IDENTITY STORE ID'  # d-1234567890 | To query SSO Users
SSO_INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-YOUR INSTANCE ARN"  # ssoins-0123456789abcdef
TAG_KEYS = [
    'Name',
    'Owner',
    'Department',
    'App',
    'Env',
    'FinanceId',
    'Deployment'
    # 'aws:autoscaling:groupName',
    # 'aws:backup:source-resource',
    # 'aws:cloudformation:logical-id',
    # 'aws:cloudformation:stack-id',
    # 'aws:cloudformation:stack-name',
    # 'aws:ec2launchtemplate:id',
    # 'aws:ec2launchtemplate:version',
    # 'aws:ecs:clusterName',
    # 'aws:ecs:serviceName',
    # 'aws:elasticfilesystem:default-backup',
    # 'aws:migrationhub:source-id',
    # 'aws:rds:primaryDBInstanceArn',
    # 'aws:secretsmanager:owningService',
    # 'aws:ssmmessages:session-id',
    # 'aws:ssmmessages:target-id',
]                  # Change the tags as per your organization needs

MANDATORY_TAGS = {}
for key in TAG_KEYS:
    MANDATORY_TAGS[key] = 'NoValue'
