# -*- coding: utf-8 -*-
"""Global variable across modules."""

# import os
# from tempfile import gettempdir
import logging

LOGGER = logging.getLogger(__name__)

# Path to store query output CSV files
# CSV_PATH = gettempdir() + '/'
CSV_PATH = 'query_output/'

# Windows user running WSL
# USER = os.getenv('USER')
# CSV_PATH = f"/mnt/c/Users/{USER}/Downloads/"

# Initialize query name to run
QUERY = None

# Initialize boto3 session variable
SESSION = None

# Custom AWS cli settings
CLI_PROFILE = 'YOUR AWS CLI PROFILE'
REGION = 'us-east-1'                          # Default region for your workloads

# Leave it empty if no Organization available and set the INCLUSION LIST variable
ROOT_ACCOUNT_ID = '123456789012'
IDENTITY_STORE_ID = 'YOUR IDENTITY STORE ID'  # d-1234567890 | To query SSO Users
SSO_INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-YOUR INSTANCE ARN"  # ssoins-0123456789abcdef

# Details required to assume IAM roles
SERVICE_ACCOUNT_ID = '123456789012'           # AWS Account to authenticate and run queries
SERVICE_ACCOUNT_ROLE = 'SERVICE ROLE'         # Only permission to assume TARGET_ACCOUNT_ROLE
TARGET_ACCOUNT_ROLE = 'TARGET SERVICE ROLE'   # IAM role with read permissions to run queries

# AWS account Alias and IDs to be included with queries
# This variable is required when no Organization is set
# i.e. INCLUSION_LIST = [{'AccountAlias': 'ALIAS', 'AccountId': '123456789012'}]
INCLUSION_LIST = []

# AWS account IDs to be excluded from queries
# use it for account of no interest or retricted access
# i.e. EXCLUSION_LIST = ['123456789012']
EXCLUSION_LIST = []

# Tagging strategy
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
]                                             # Change the tags as per your organization needs

MANDATORY_TAGS = {}
for key in TAG_KEYS:
    MANDATORY_TAGS[key] = 'NoValue'
