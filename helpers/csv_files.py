# -*- coding: utf-8 -*-

"""Manipulate CSV files Module."""

import csv
import os
import logging

import helpers.config   as     config
from helpers.boto3_func import get_tag_keys

LOGGER = logging.getLogger(__name__)


def csv_writer(file_name: str, rows: list, headers: list) -> None:
    """Generate a CSV file."""
    with open(file_name, 'w', encoding='UTF8') as f:
        writer = csv.writer(f)
        if headers:
            writer.writerow(headers)

        for row in rows:
            writer.writerow(row)

    if bool(os.path.exists(file_name) and os.path.getsize(file_name) > 0):
        LOGGER.info(f'CSV file {file_name} has been created.')
    else:
        LOGGER.error('Whach out the CSV file creation failed.')

    return


def csv_to_list(file_name: str) -> list:
    """Import CSV file to a list of strings."""
    try:
        with open(file_name, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            data = list(reader)

    except IOError as e:
        LOGGER.error(f"File not found. {e}")
        data = None

    return data


def query_to_csv(result: list, resource_csv_headers: list, file_path: str):
    """Generate a CSV file que the query results."""
    # Default headers
    csv_headers = [
        'AWS Account ID',
        'AWS Account Alias',
        'AWS Region',
    ]

    # Add resource columns of interest
    csv_headers += resource_csv_headers

    # Add tag keys as column names
    csv_headers += get_tag_keys(config.MANDATORY_TAGS)

    csv_writer(file_path, result, csv_headers)
