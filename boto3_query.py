# -*- coding: utf-8 -*-
"""Run AWS resource queries across an AWS Organization.

Usage example:
Query VPCs at all AWS accounts in the organization within all available regions

> python3 boto3_query.py -n vpc
"""

from re import match
import click  # pylint: disable=import-error

from classes.csv_file import CsvHandler
from helpers import config

from helpers import LOGGER, SETUP
from helpers.resources import get_resources
from helpers.boto3_func import regions_to_query, add_region, loop_function, \
                               try_get_value, get_resource_tags, \
                               validate_sts_token, accounts_to_query


def query_by_account(aws: dict) -> list:
    """Trigger a query at each active region by AWS account in parallel."""

    try:     # Check if the query is multi-region or not
        regions = SETUP[config.QUERY]['Region']
    except:  # pylint: disable=bare-except # noqa: E722
        regions = regions_to_query(config.REGION, aws['AccountId'])

    # Generate a list with required region/s for the query
    query_region = add_region(aws, regions)

    return loop_function(query_region, resources, False)


def resources(aws: dict) -> list:
    """Run query with an AWS account and region."""
    csv_rows = []   # Initialize rows list

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


def aws_account_id_callback(ctx, param, value):  # pylint: disable=unused-argument # noqa: E501
    """Validate AWS Account ID is 12 integer digits."""
    if not match('\d{12}', value):  # pylint: disable=anomalous-backslash-in-string # noqa: W605, E501
        raise click.BadParameter('AWS account ID must be 12 digits.')

    return value


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
    default=None,
    show_default=True,
    nargs=1,
    help='AWS Region'
)
def run_query(name: str, account: str, region: str) -> None:
    """Run an AWS resource query by service name."""

    # Check if the user running the query is authenticated.
    caller = validate_sts_token()
    LOGGER.info("Query started by %s", caller['Arn'])

    # Set query paramenters to share the value across modules
    config.QUERY = name
    config.REGION = region

    # Loop through all accounts/regions to run an AWS SDK query in parallel
    results = loop_function(
        accounts_to_query(account),  # List of AWS account/s to run a query on
        query_by_account,            # Query to run per account in paralallel
        True                         # Flag to display result summary
    )

    # Send the results to a csv file locally
    csv_file = CsvHandler(f"{config.CSV_PATH}{name}")
    csv_file.query_to_csv(SETUP[name]['Headers'], results)


if __name__ == '__main__':
    run_query()  # pylint: disable=no-value-for-parameter
