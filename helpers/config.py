# -*- coding: utf-8 -*-
"""Global variable across modules."""

import os
from classes.session import AwsSession

# Initialize query name to run
QUERY = ''

# Customer specific variables
CLI_PROFILE        = 'YOUR AWS CLI PROFILE'
SERVICE_ACCOUNT_ID = '123456789012'             # It could be your Org root account ID
SERVICE_ROLE_NAME  = 'YOUR SERVICE ROLE'        # i.e. AWSControlTowerExecution
REGION             = 'ap-southeast-2'           # Default region
IDENTITY_STORE_ID  = 'YOUR IDENTITY STORE ID'   # d-1234567890  | The script can run queries on your SSO Users
SSO_INSTANCE_ARN   = "arn:aws:sso:::instance/ssoins-YOUR INSTANCE ARN"  # ssoins-0123456789abcdef
MANDATORY_TAGS     = {          # Change the tags as per your organization requirements
    'Name':       'NoValue',
    'Owner':      'NoValue',
    'Department': 'NoValue',
    'App':        'NoValue',
    'Env':        'NoValue',
    'FinanceId':  'NoValue',
    'Deployment': 'NoValue'
}

# Initialize boto3 session
_session_obj = AwsSession(CLI_PROFILE)
SESSION = _session_obj.cli()

USER = os.getenv('USER')

# Path to drop off all query output files
CSV_PATH = 'queries/'
# CSV_PATH = '/tmp/'

# If you run the script on WSL and Windows user and WSL user are the same.
# CSV_PATH = f"/mnt/c/Users/{USER}/Downloads/"
# CSV_PATH = f"/mnt/c/Users/{USER}/Khalil/Documents/C&I/boto3_queries/"
