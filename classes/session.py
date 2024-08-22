# -*- coding: utf-8 -*-
"""Class to set boto3 session with MFA cache."""

import os
import sys
import logging
from boto3 import Session
from botocore.credentials import JSONFileCache
from botocore.exceptions import ClientError

logger = logging.getLogger("boto_session")
logger.setLevel(logging.INFO)


def display_exception(msg):
    """Show exception messages and abort."""
    logger.error("ERROR | Boto3 session failed with error message below:\n %s", msg)
    sys.exit(1)


class AwsSession:
    """Manage boto3 session."""

    def __init__(self, profile: str, region='ap-southeast-2') -> None:
        """Initialize class variables."""
        self.profile = profile
        self.region = region

    def cli(self, auth='sso') -> object:
        """Start a session to be used from CLI and check if the credentials are
        cached already."""
        # aws cli cache location per authentication method
        if auth == 'sso':
            cache = '.aws/sso/cache'
        else:
            cache = '.aws/cli/cache'

        cli_cache = os.path.join(os.path.expanduser('~'), cache)

        try:
            session = Session(profile_name=self.profile, region_name=self.region)
        except ClientError as error:
            display_exception(error)
        except Exception as error:  # pylint: disable=broad-except
            display_exception(error)

        try:
            session._session.get_component(  # pylint: disable=protected-access
                'credential_provider'
            ).get_provider('assume-role').cache = JSONFileCache(cli_cache)
        except ClientError as error:
            display_exception(error)
        except Exception as error:  # pylint: disable=broad-except
            display_exception(error)

        return session

    def lambdas(self) -> object:
        """Start a session to be used in a Lambda funcion."""
        try:
            session = Session(region_name=self.region)
        except Exception as error:  # pylint: disable=broad-except
            display_exception(error)

        return session
