# -*- coding: utf-8 -*-
"""Run AWS resource queries across an AWS Organization.

Usage example:
Query VPCs at all AWS accounts in the organization within all available regions:

> python3 boto3_query.py -n vpc
"""

from logging import getLogger
from re import match
import click

from helpers import config
from helpers import SETUP
from helpers.resources import get_resources
from helpers.boto3_func import accounts_to_query, regions_to_query, add_region, \
                               try_get_value, get_resource_tags

from classes.csv_file import CsvHandler
from classes.python_sdk import AwsSession, AwsPythonSdk
from classes.looper import Looper

LOGGER = getLogger(__name__)


def resources_by_region(aws: dict) -> list:
    """Run query with an AWS account and region."""
    csv_rows = []  # Initialize rows list

    # Loop through aws resources
    for r in get_resources(aws, config.QUERY):
        # Start row with common values to all queries
        csv_row = [str(aws['AccountId']), aws['AccountAlias'], aws['Region']]

        # Add selected resource values from boto3 response
        for header in SETUP[config.QUERY]['Headers']:
            csv_row.append(try_get_value(r, header))

        # Add selected tag values
        csv_row += get_resource_tags(r)

        # Add new row
        csv_rows.append(csv_row)

    return csv_rows


def query_by_account(aws: dict) -> list:
    """Trigger a query at each active region by AWS account in parallel or to a
    single AWS region if it is specified as an argument."""

    # If Region is not declared in the SETUP variable it means the query
    # is multi-region
    try:
        regions = SETUP[config.QUERY]['Region']
    except KeyError:
        regions = regions_to_query(config.REGION, aws['AccountId'])

    # Generate a list with required region/s for the query
    aws_regions = add_region(aws, regions)

    return Looper(aws_regions, resources_by_region).parallel_return()


def aws_account_id_callback(ctx, param, value):  # pylint: disable=W0613
    """Validate AWS Account ID is valid."""
    if match(r'\d{12}', value) and len(value) == 12:
        return value

    raise click.BadParameter('AWS account ID must be 12 digits.')


@click.command()
@click.option(
    '-n',
    '--name',
    default='ec2',
    show_default=True,
    nargs=1,
    type=click.Choice(SETUP.keys(), case_sensitive=False),
    help='Query name to run'
)
@click.option(
    '-a',
    '--account',
    default='111111111111',
    show_default=False,
    nargs=1,
    type=str,
    callback=aws_account_id_callback,
    help='AWS Account ID to run the query on.'
)
@click.option(
    '-r',
    '--region',
    default=config.REGION,
    show_default=True,
    nargs=1,
    help='AWS Region'
)
def run_query(name: str, account: str, region: str) -> None:
    """Run an AWS resource query by service name."""

    # Set query parameters to share the values across modules
    config.QUERY = name
    config.REGION = region
    config.SESSION = AwsSession(config.CLI_PROFILE, region, authentication="sso").cli()

    # Check if the user running the query is authenticated.
    caller = AwsPythonSdk(config.SERVICE_ACCOUNT_ID, 'sts').validate_sts_token()
    LOGGER.info("Query started by %s", caller['Arn'])

    # Loop through all accounts/regions to run an AWS SDK query in parallel
    results = Looper(
        accounts_to_query(account),  # List of AWS account/s to run a query
        query_by_account,            # Function to run per account in parallel
    ).parallel_return(summary=True)

    # Send the results to a csv file
    CsvHandler(f"{config.CSV_PATH}{name}").query_to_csv(SETUP[name]['Headers'], results)


if __name__ == '__main__':
    run_query()  # pylint: disable=E1120
