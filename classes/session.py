# -*- coding: utf-8 -*-
"""Class to construct boto3 session with MFA cache."""

import os
import sys
import botocore
import boto3
import logging

logger = logging.getLogger("boto_session")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s", "%m/%d/%Y %I:%M:%S %p")
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)


def display_exception(msg):
    """Show excepion messages and abort."""
    logger(f"ERROR | Boto3 session failed with error message below:\n {msg}")
    sys.exit(1)


class AwsSession:
    """Manage boto3 session."""

    def __init__(self, profile: str, region='ap-southeast-2') -> None:
        """Initialize class variables."""
        self.profile = profile
        self.region = region

    def cli(self) -> object:
        """Start a session to be used from CLI and check if the credentials are cached already."""
        cli_cache = os.path.join(os.path.expanduser('~'), '.aws/sso/cache')     # it can be .aws/cli/cache instead
        try:
            session = boto3.Session(profile_name=self.profile,
                                    region_name=self.region)

        except botocore.exceptions.ProfileNotFound as error:
            display_exception(error)

        except Exception as error: # pylint: disable=broad-except
            display_exception(error)

        try:
            session._session.get_component('credential_provider').get_provider('assume-role').cache = botocore.credentials.JSONFileCache(cli_cache) # pylint: disable=protected-access
        except Exception as error: # pylint: disable=broad-except
            display_exception(error)

        return session

    def lambdas(self) -> object:
        """Start a session to be used in a Lambda funcion."""
        try:
            session = boto3.Session(region_name=self.region)
        except Exception as error: # pylint: disable=broad-except
            display_exception(error)

        return session
