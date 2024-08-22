# -*- coding: utf-8 -*-
"""Class to handle ARN values individually.

ARN format:

arn:partition:service:region:account-id:resource-id
arn:partition:service:region:account-id:resource-type/resource-id
arn:partition:service:region:account-id:resource-type:resource-id
"""

import logging

LOGGER = logging.getLogger(__name__)


class ArnHandler:
    """Manage Dynamo DB client & resources."""

    def __init__(self, arn: str) -> None:
        """Handle Dynamo DB table."""
        self.arn = arn
        self.arn_splited = arn.split(':')

    def partition(self) -> str:
        """Fetch ARN partition."""
        return self.arn_splited[1]

    def service(self) -> str:
        """Fetch ARN service."""
        return self.arn_splited[2]

    def region(self) -> str:
        """Fetch ARN region."""
        return self.arn_splited[3]

    def account(self) -> str:
        """Fetch ARN account id."""
        return self.arn_splited[4]

    def resource_type(self) -> str:
        """Fetch ARN resource_type."""
        if '/' in self.arn_splited[5]:
            resource_details = self.arn_splited[5].split('/')
            resource_type = resource_details[0]
        else:
            if len(self.arn_splited) == 6:
                resource_type = ''
            else:
                resource_type = self.arn_splited[5]

        return resource_type

    def resource_id(self) -> str:
        """Fetch ARN resource_id."""
        if '/' in self.arn_splited[5]:
            resource_details = self.arn_splited[5].split('/')
            # remove resource type from the list
            del resource_details[0]
            # add the full path for the resource ID
            resource_id = ''
            for r in resource_details:
                if resource_id:
                    resource_id = resource_id + "/" + r
                else:
                    resource_id = r

        else:
            if len(self.arn_splited) == 6:
                resource_id = self.arn_splited[5]
            else:
                resource_id = self.arn_splited[6]

        return resource_id

    def resource_version(self) -> str:
        """Get ARN resource version."""
        if len(self.arn_splited) == 8:
            resource_version = self.arn_splited[7]
        else:
            resource_version = None

        return resource_version

    def details(self) -> None:
        """Display ARN and all columns explained."""
        print(f"\nARN..........: {self.arn}\n")
        print(f"Partition....: {self.partition()}")
        print(f"Service......: {self.service()}")
        print(f"Region.......: {self.region()}")
        print(f"Account ID...: {self.account()}")
        print(f"Resource type: {self.resource_type()}")
        print(f"Resource ID..: {self.resource_id()}")
        print(f"Resource Ver.: {self.resource_version()}")


def usage_example():
    """How to use the class."""
    arn = "arn:partition:service:region:account-id:resource-type/resource-id"
    arn_obj = ArnHandler(arn)
    arn_obj.details()

    print(arn_obj.resource_type())
