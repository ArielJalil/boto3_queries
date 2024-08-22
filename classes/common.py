# -*- coding: utf-8 -*-
"""Generic classes to support queries."""

from logging import getLogger
from datetime import datetime
from dateutil.parser import parse

LOGGER = getLogger(__name__)


class Color:  # pylint: disable=R0902, R0903
    """Choose color to print messages."""

    def __init__(self) -> None:
        """Class constructor."""
        self.no_color = '\033[0m'
        self.blue = '\033[94m'
        self.violet = '\033[95m'
        self.green = '\033[92m'
        self.red = '\033[91m'
        self.yellow = '\033[93m'
        self.beige = '\033[36m'
        self.black = '\033[30m'
        self.white = '\033[37m'
        self.pink = '\033[31m'
        self.cyan = '\033[96m'
        self.grey = '\033[90m'
        self.bold = '\033[1m'
        self.underline = '\033[4m'
        self.strikethrough = '\033[9m'


class ByteTo:
    """Transform bytes in to kb mb gb an so on."""

    def __init__(self, byte) -> None:
        """Class constructor."""
        self.byte = byte

    def kilo(self):
        """Transform to MB."""
        return self.byte / 1024

    def mega(self):
        """Transform to MB."""
        return self.byte / 1024 ** 2

    def giga(self):
        """Transform to MB."""
        return self.byte / 1024 ** 3

    def tera(self):
        """Transform to MB."""
        return self.byte / 1024 ** 4

    def peta(self):
        """Transform to MB."""
        return self.byte / 1024 ** 5

    def exa(self):
        """Transform to MB."""
        return self.byte / 1024 ** 6

    def zetta(self):
        """Transform to MB."""
        return self.byte / 1024 ** 7

    def yotta(self):
        """Transform to MB."""
        return self.byte / 1024 ** 8


class AwsDate:
    """Handle date fields from boto3 responses."""

    def __init__(self, date: any) -> None:
        """Class constructor."""
        self.date = date

    def format_date(self) -> str:
        """
        Format date field into string like: DD/MM/YYYY HH:MM:SS UTC
        """
        return datetime.strptime(str(self.date), '%Y-%m-%d %H:%M:%S%z').strftime('%-d/%m/%y %-H:%M')

    def days_since(self) -> int:
        """Count days since today to a specific."""
        if isinstance(self.date, str):
            get_date_obj = parse(self.date)
            date_obj = get_date_obj.replace(tzinfo=None)
        else:
            date_obj = self.date.replace(tzinfo=None)

        diff = datetime.now() - date_obj
        return diff.days

    def days_to(self) -> int:
        """Count days since specific date to today."""
        if isinstance(self.date, str):
            get_date_obj = parse(self.date)
            date_obj = get_date_obj.replace(tzinfo=None)
        else:
            date_obj = self.date.replace(tzinfo=None)

        diff = date_obj - datetime.now()
        return diff.days
