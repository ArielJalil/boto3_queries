# -*- coding: utf-8 -*-
"""Helper functions for Looper class."""

import logging

from classes.looper import Looper

LOGGER = logging.getLogger(__name__)


def loop_function(items: list, f_to_call: object, sumary_flag: bool) -> list:
    """Run a loop using parallel processing."""
    looper = Looper(items, f_to_call)
    return looper.parallel_return(summary=sumary_flag)


def make_list_acc_region(regions: list, aws: dict) -> list:
    """Make a list of dictionaries with AWS Account and Region details."""
    account_regions = list()
    for region in regions:
        account_regions.append(
            {
                'AccountId': aws['AccountId'],
                'AccountAlias': aws['AccountAlias'],
                'Region': region
            }
        )

    return account_regions
