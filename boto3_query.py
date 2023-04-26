# -*- coding: utf-8 -*-
"""
Run AWS resource queries across an AWS Organization.

Usage example:
Query VPCs with all accounts in the organization within all regions:

> python3 boto3_query.py -n vpc

"""
import click
import helpers.config as config

from re                 import match
from helpers            import LOGGER, SETUP, DATE
from helpers.csv_files  import query_to_csv
from helpers.list_func  import get_dic_item
from helpers.boto3_func import get_active_accounts, validate_sts_token
from helpers.looper     import query_by_account, loop_function


def get_accounts_to_query(account_id: str) -> list:
    """Return a list with the AWS account/s where the query will run."""
    aws_accounts = get_active_accounts()    # List of active AWS accounts in the Org
    if account_id != '111111111111':
        aws_accounts = [get_dic_item(aws_accounts, 'AccountId', account_id)]
        if aws_accounts == [None]:
            LOGGER.error('Account ID %s does not exist in the Organization.', account_id)
            exit(1)

    return aws_accounts


def aws_account_id_callback(ctx, param, value):
    """Validate AWS Account ID is valid."""
    if match('\d{12}', value):
        return value
    else:
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
def run_query(name: str, account: str) -> None:
    """Run an AWS resource query by service name."""
    # Check if the user running the query is authenticated.
    caller = validate_sts_token()
    LOGGER.info(f"Query started by {caller['Arn']}")

    # Query paramenters
    config.QUERY = name
    accounts_to_query = get_accounts_to_query(account)

    # Loop through all accounts/regions and run a boto3 query in parallel
    result = loop_function(
        accounts_to_query,  # List of AWS account/s to run a query on
        query_by_account,   # Fan out queries per account in paralallel
        True                # Flag to display result summary
    )

    # Send the results to a csv file
    csv_dir = '/tmp/'
    query_to_csv(
        result,                            # Query result in a list of lists
        SETUP[name]['Headers'],            # Resource headers
        f'{csv_dir}{name}_{DATE}.csv'      # CSV output file
    )


if __name__ == '__main__':
    run_query()
