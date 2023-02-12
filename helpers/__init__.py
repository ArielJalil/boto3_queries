"""Helper modules."""

import logging

from classes.session import AwsSession

# Customer specific variables
cli_profile = 'your_cli_profile_name'    # AWS CLI profile that give you access to your service account
SERVICE_ACCOUNT_ID = '123456789012'      # AWS Account ID of your Organization root account
SERVICE_ROLE_NAME = 'your_service_role'  # IAM role in target accounts i.e. AWSControlTowerExecution

# Choose the AWS cli profile name and region | ap-southeast-2 by default
session_obj = AwsSession(cli_profile)
SESSION = session_obj.cli()

MANDATORY_TAGS = {                       # Tags of interest that will be used in the query output
    'CostCode':        'NoValue',
    'BusUnit':         'NoValue',
    'App':             'NoValue',
    'Env':             'NoValue',
    'Owner':           'NoValue',
    'Deployment_type': 'NoValue',
    'Name':            'NoValue'
}


logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=logging.INFO
)

LOGGER = logging.getLogger(__name__)
