# -*- coding: utf-8 -*-
"""Class to handle CSV files."""

import logging
import os
import csv
from datetime import datetime
from helpers import config

LOGGER = logging.getLogger(__name__)


class CsvHandler:
    """Manage CSV files."""

    def __init__(self, file_name: str) -> None:
        """Handle a CSV file."""
        self.file_name = f"{file_name}"

    def writer(self, rows: list, headers: list) -> None:
        """Generate a CSV file."""
        current_time = datetime.now().strftime("%Y%m%d-%H%M%S")
        full_name = f"{self.file_name}_{current_time}.csv"
        with open(full_name, 'w', encoding='UTF8') as f:
            writer = csv.writer(f)
            if headers:
                writer.writerow(headers)

            for row in rows:
                writer.writerow(row)

        if bool(os.path.exists(full_name) and os.path.getsize(full_name) > 0):
            LOGGER.info('CSV file %s has been created.', full_name)
        else:
            LOGGER.error('Whach out. The CSV file creation failed.')

    def to_list(self) -> list:
        """Import CSV file to a list of strings."""
        try:
            with open(f"{self.file_name}.csv", newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                data = list(reader)

        except IOError as e:
            LOGGER.error("File not found. %s", e)
            data = None

        return data

    def query_to_csv(self, resource_csv_headers: list, result: list) -> None:
        """Generate a CSV file que the query results."""
        # Default headers
        csv_headers = ['AWS Account ID', 'AWS Account Alias', 'AWS Region']

        # Add resource columns of interest
        csv_headers += resource_csv_headers

        # Add tag keys as column names
        csv_headers += config.TAG_KEYS
        csv_headers.append('CountMissedTag')

        self.writer(result, csv_headers)
