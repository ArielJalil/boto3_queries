# -*- coding: utf-8 -*-
"""Class for handle STS Assume Role on AWS services."""

import logging
from botocore.exceptions import ClientError  # pylint: disable=import-error

LOGGER = logging.getLogger(__name__)


class StsObject:
    """Assume IAM role with STS for specified service."""

    def __init__(
        self, session: object, account_id: str, role: str, duration=900
    ) -> object:
        """Initialize class variables."""
        self.session = session
        self.account_id = account_id
        self.role = role
        self.duration = duration

    def assume_role(self):
        """Assume Service Role function."""
        client = self.session.client('sts')

        try:
            sts = client.assume_role(
                RoleArn=f"arn:aws:iam::{self.account_id}:role/{self.role}",
                RoleSessionName=self.role,
                DurationSeconds=self.duration
            )
        except ClientError as erro:
            LOGGER.error("STS assume role failed: \n%s", erro)
            sts = None

        return sts

    def get_client(self, aws_service: str, aws_region='ap-southeast-2') -> object:  # noqa: E501
        """Set boto3 client using STS token."""
        client = None
        sts = self.assume_role()
        if sts:
            try:
                client = self.session.client(
                    aws_service,
                    aws_region,
                    aws_access_key_id=sts['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts['Credentials']['SecretAccessKey'],  # noqa: E501
                    aws_session_token=sts['Credentials']['SessionToken']
                )
            except ClientError as erro:
                LOGGER.error(
                    "Boto3 client %s service failed:\n%s", aws_service, erro
                )

        return client

    def get_resource(self, aws_service: str, region='ap-southeast-2') -> object:  # noqa: E501
        """Set boto3 resource using STS token."""
        resource = None
        sts = self.assume_role()
        try:
            resource = self.session.resource(
                aws_service,
                region,
                aws_access_key_id=sts['Credentials']['AccessKeyId'],
                aws_secret_access_key=sts['Credentials']['SecretAccessKey'],
                aws_session_token=sts['Credentials']['SessionToken']
            )
        except ClientError as erro:
            LOGGER.error(
                "Boto3 resource for %s service failed:\n%s", aws_service, erro
            )

        return resource
