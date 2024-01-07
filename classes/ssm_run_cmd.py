# -*- coding: utf-8 -*-
"""Class to handle SSM service."""

import logging
from time import sleep
from botocore.exceptions import ClientError  # pylint: disable=import-error
from helpers.boto3_func import paginate

LOGGER = logging.getLogger(__name__)


def _get_ec2_ids(inventory: list) -> list:
    """Extract ec2 IDs from live instances in the ssm inventory."""
    ec2_ids = []
    for i in inventory:
        if i['PingStatus'] == 'Online':
            ec2_ids.append(i['InstanceId'])

    return ec2_ids


def _split_list(full_list: list, chunk_size: int) -> list:
    """Generate n number of smaller chunks from a list."""
    for i in range(0, len(full_list), chunk_size):
        yield full_list[i:i + chunk_size]


class SsmRunCommand:
    """Manage boto3 session."""

    def __init__(self, ssm_client: object, filters: list, command_to_run: str) -> None:
        """Initialize class variables."""
        self.ssm = ssm_client
        self.filters = filters
        self.cmd_to_run = command_to_run

    def get_ec2_inventory(self) -> list:
        """Get EC2 inventory from SSM service."""
        if self.filters:
            ssm_inventory = list(
                paginate(
                    self.ssm,
                    'describe_instance_information',
                    Filters=self.filters
                )
            )
        else:
            ssm_inventory = list(
                paginate(
                    self.ssm,
                    'describe_instance_information'
                )
            )

        return ssm_inventory

    def run_cmd_on_targets(self, ec2_ids: list) -> str:
        """Issue send_command API call to SSM service."""
        try:
            result = self.ssm.send_command(
                Targets=[
                    {
                        'Key': 'InstanceIds',
                        'Values': ec2_ids
                    }
                ],
                DocumentName='AWS-RunShellScript',
                TimeoutSeconds=30,
                Comment='Check bamboo agent nodes',
                Parameters={
                    'commands': [
                        self.cmd_to_run
                    ]
                },
                MaxConcurrency='10'
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceId':
                LOGGER.error("Instance ID batch failed:\n%s", ec2_ids)
                return ''

            if e.response['Error']['Code'] == 'UnsupportedPlatformType':
                LOGGER.error(
                    "Unsupported platform (Windows) instance found at batch:\n%s", ec2_ids
                )
            else:
                LOGGER.error("ERROR: %s", e)

            return ''

        return result['Command']['CommandId']

    def get_run_cmd_outputs(self, command_id: str) -> list:
        """Issue list_command_invocations API call to SSM service."""
        # Wait 3 seconds for the command to be executed
        sleep(3)
        # Fetch commands output
        list_command_invocations = self.ssm.list_command_invocations(
            CommandId=command_id,
            MaxResults=50,
            Details=True
        )
        cmd_out = list_command_invocations['CommandInvocations']

        while 'NextToken' in list_command_invocations:
            next_token = list_command_invocations['NextToken']
            list_command_invocations = self.ssm.list_command_invocations(
                CommandId=command_id,
                MaxResults=10,
                Details=True,
                NextToken=next_token
            )
            cmd_out = cmd_out + list_command_invocations['CommandInvocations']

        cmd_outs = []
        for out in cmd_out:
            cmd_outs.append(out['CommandPlugins'][0]['Output'].split('\n'))

        return cmd_outs

    def run_cmd(self) -> list:
        """Gathe SSM Run Command output from all targets."""
        cmd_outs = []
        ec2_ids = _get_ec2_ids(self.get_ec2_inventory())

        # Split the list of ec2 id targets in chunks of 10
        ec2_ids_chunks = list(_split_list(ec2_ids, 10))

        # SSM run command cannot be issued on large number of targets
        for ec2_ids_chunk in ec2_ids_chunks:
            cmd_outs += self.get_run_cmd_outputs(
                self.run_cmd_on_targets(ec2_ids_chunk)
            )

        return cmd_outs
