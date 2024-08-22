# -*- coding: utf-8 -*-
"""Class to handle AWS SDK for Python - Boto3."""

import sys
import os
from logging import getLogger
from boto3 import Session
from botocore.credentials import JSONFileCache
from botocore.exceptions import ProfileNotFound, SSOTokenLoadError, \
                                ClientError, UnauthorizedSSOTokenError
from helpers import config

MODULE_LOGGER = getLogger(__name__)


class AwsSession:
    """Manage boto3 session."""
    _class_logger = MODULE_LOGGER.getChild(__qualname__)

    def __init__(self, profile: str, region=config.REGION, authentication='sso') -> None:
        """Initialize class."""
        self._instance_logger = self._class_logger.getChild(str(id(self)))
        self.profile = profile
        self.region = region
        if authentication == 'sso' or authentication == 'cli':  # pylint: disable=R1714
            self.authentication = authentication
        else:
            self._instance_logger.error(
                'Allowed values for authentication variable are sso or cli.'
            )
            sys.exit(-1)

    def cli(self):
        """Start a session to be used from CLI."""
        cache = f".aws/{self.authentication}/cache"

        cli_cache = os.path.join(os.path.expanduser('~'), cache)
        cli_session = None
        try:
            cli_session = Session(
                profile_name=self.profile,
                region_name=self.region
            )

        except ProfileNotFound as e:
            self._instance_logger(e)
            sys.exit(-1)

        cli_session._session.get_component(  # pylint: disable=W0212
            'credential_provider'
        ).get_provider(
            'assume-role'
        ).cache = JSONFileCache(
            cli_cache
        )

        return cli_session

    def lambdas(self) -> object:
        """Start a session to be used in a Lambda funcion."""
        try:
            session = Session(region_name=self.region)
        except Exception as e:  # pylint: disable=W0718
            self._instance_logger.error(e)
            sys.exit(-1)

        return session


class Paginator:  # pylint: disable=R0903
    """Boto3 generic paginator."""
    _class_logger = MODULE_LOGGER.getChild(__qualname__)

    def __init__(self, client: object, method: str):
        """Class constructor."""
        self._instance_logger = self._class_logger.getChild(str(id(self)))
        self.client = client
        self.method = method

    def paginate(self, **kwargs) -> any:
        """Paginate boto3 client methods."""
        try:
            paginator = self.client.get_paginator(self.method)

        except KeyError as e:
            self._instance_logger.error(f"Paginator method not found: {e}")
            sys.exit(-1)

        except ClientError as e:
            self._instance_logger.error(f"Fail getting paginator: {e}")
            sys.exit(-1)

        try:
            for page in paginator.paginate(**kwargs).result_key_iters():
                for result in page:
                    yield result

        except UnboundLocalError as e:
            self._instance_logger.error(f"Paginator failure: {e}")
            sys.exit(-1)

        except ClientError as e:
            self._instance_logger.error(f"Paginator failure: {e}")
            sys.exit(-1)


class BotoType:
    """Set boto3 client."""
    _class_logger = MODULE_LOGGER.getChild(__qualname__)

    def __init__(self, session: object) -> None:
        """Class constructor."""
        self._instance_logger = self._class_logger.getChild(str(id(self)))
        self.session = session

    def client(self, client: str) -> object:
        """Set boto3 client."""
        try:
            return self.session.client(client)
        except Exception as e:  # pylint: disable=W0718
            self._instance_logger.error(f"Boto3 client initialization failure: {e}")
            sys.exit(-1)

    def resource(self, resource: str) -> object:
        """Set boto3 resource."""
        try:
            return self.session.resource(resource)
        except Exception as e:  # pylint: disable=W0718
            self._instance_logger.error(f"Boto3 resource initialization failure: {e}")
            sys.exit(-1)


class Sts:
    """Assume role with STS for specified service."""
    _class_logger = MODULE_LOGGER.getChild(__qualname__)

    def __init__(self, session: object, account_id: str, role: str, duration=900) -> object:
        """Initialize class variables."""
        self._instance_logger = self._class_logger.getChild(str(id(self)))
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
            self._instance_logger.error(f"STS assume role failed: {erro}")
            sts = None

        return sts

    def get_client(self, aws_service: str, aws_region='ap-southeast-2') -> object:
        """Set boto3 client using STS token."""
        sts = self.assume_role()
        if sts:
            try:
                client = self.session.client(
                    aws_service,
                    aws_region,
                    aws_access_key_id=sts['Credentials']['AccessKeyId'],
                    aws_secret_access_key=sts['Credentials']['SecretAccessKey'],
                    aws_session_token=sts['Credentials']['SessionToken']
                )
            except ClientError as erro:
                self._instance_logger.error(f"Boto3 client {aws_service} service failed:\n{erro}")
                client = None

        return client

    def get_resource(self, aws_service: str, region='ap-southeast-2') -> object:
        """Set boto3 resource using STS token."""
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
            self._instance_logger.error(f"Boto3 resource for {aws_service} service failed:\n{erro}")
            resource = None

        return resource


class AwsPythonSdk:
    """Assume role and set Boto3 object."""
    _class_logger = MODULE_LOGGER.getChild(__qualname__)

    def __init__(self, account_id: str, service: str, region=config.REGION) -> None:
        """Class constructor."""
        self._instance_logger = self._class_logger.getChild(str(id(self)))
        self.account_id = account_id
        self.service = service
        self.region = region
        self.session = config.SESSION
        self.role = config.SERVICE_ROLE_NAME
        self.service_account = config.SERVICE_ACCOUNT_ID

    def client(self):
        """Get boto3 client in target AWS Account."""
        # Service IAM Role might not be deployed at the service account
        if self.account_id != self.service_account:
            # Set boto3 client using STS credentials
            client = Sts(
                self.session, self.account_id, self.role
            ).get_client(self.service, self.region)
        else:
            # The service account is already authenticated and it will use current user's IAM role
            client = self.session.client(self.service, self.region)

        return client

    def resource(self):
        """Get boto3 resource in target AWS Account."""
        # Service IAM Role might not be deployed at the service account
        if self.account_id != self.service_account:
            # Set boto3 resource using STS credentials
            client = Sts(
                self.session, self.account_id, self.role
            ).get_resource(self.service, self.region)
        else:
            # The service account is already authenticated and it will use current user's IAM role
            client = self.session.resource(self.service, self.region)

        return client

    def validate_sts_token(self) -> str:
        """Check if current user is already authenticated."""
        sts = self.client()

        try:
            caller = sts.get_caller_identity()
        except UnauthorizedSSOTokenError as e:
            self._instance_logger.error("Current user validation failed: %s", e)
            sys.exit(-1)
        except SSOTokenLoadError as e:
            self._instance_logger.error("Current user validation failed: %s", e)
            sys.exit(-1)
        except ClientError as e:
            self._instance_logger.error("Current user validation failed: %s", e)
            sys.exit(-1)

        return caller

    def get_regions(self) -> any:
        """Gets Regions Enabled for the AWS Account."""
        ec2 = self.client()
        try:
            response = ec2.describe_regions(AllRegions=False)
        except ClientError as e:
            self._instance_logger.error('Error getting list of regions: %s', e)
            return

        for region in response['Regions']:
            yield region['RegionName']

    def org_accounts(self) -> any:
        """Get the list of active AWS accounts in the Organization."""
        org = self.client()
        for account in Paginator(org, 'list_accounts').paginate():
            if account['Status'] == 'ACTIVE' and account['Id'] not in config.EXCLUSION_LIST:
                yield {
                    'AccountId': account['Id'],
                    'AccountAlias': account['Name']
                }
            else:
                self._instance_logger.info(f"AWS Account {account['Name']} in status {account['Status']} was excluded.")  # pylint: disable=C0301
