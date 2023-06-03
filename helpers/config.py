# -*- coding: utf-8 -*-
"""Global variable across modules."""

# Initialize boto3 session
SESSION = None

# Initialize query name to run
QUERY = ''

# Customer specific variables
CLI_PROFILE        = 'YOUR AWS CLI PROFILE'
SERVICE_ACCOUNT_ID = '123456789012'             # It could be your Org root account ID
SERVICE_ROLE_NAME  = 'YOUR SERVICE ROLE'        # i.e. AWSControlTowerExecution
REGION             = 'ap-southeast-2'           # Default region
IDENTITY_STORE_ID  = 'YOUR IDENTITY STORE ID'   # d-1234567890  | The script can run queries on your SSo Users
SSO_INSTANCE_ARN   = "arn:aws:sso:::instance/ssoins-YOUR INSTANCE ARN"  # ssoins-0123456789abcdef
MANDATORY_TAGS     = {          # Change the tags as per your requirements
    'BusUnit':      'NoValue',
    'CostCode':     'NoValue',
    'Env':          'NoValue',
    'Owner':        'NoValue',
    'Name':         'NoValue',
    'App':          'NoValue',
    'Terraform':    'NoValue'
}
