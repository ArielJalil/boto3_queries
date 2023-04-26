# -*- coding: utf-8 -*-
"""General useful functions."""

from itertools import groupby


def get_dic_item(list_of_dic: list, key: str, value: str) -> dict:
    """Find item from a list of dictionaries by key and value"""
    return next(
        (item for item in list_of_dic if item[key] == value),
        None
    )


def get_dic_item_by_key_pair(list_of_dic: list, key_pair: dict) -> dict:
    """Get single item from table by key."""
    for key, value in key_pair.items():
        return next(
            (x for x in list_of_dic if x[key] == value),
            None
        )


def sort_dic_list(list_of_dic: list, key: str) -> list:
    """Generate a sorted list of values of an specific key from a list of dictionaries."""
    return sorted(
        [x[key] for x in list_of_dic]
    )


def get_sorted_items(list_of_dic: list, key: str) -> list:
    """Sort a list of dictionaries by a key."""
    return sorted(
        list_of_dic,
        key=lambda k: k[key]
    )


def get_grouped_items(list_of_dic: list, group_by: str, sort_by: str) -> list:
    """Generate a list of dictionaries grouped and sorted by specific keys."""

    sorted_list = get_sorted_items(list_of_dic, group_by)

    for group_key, grouped_items in groupby(sorted_list, key=lambda k: k[group_by]):

        item_group = {
            "grouped_by": group_key,
            "grouped_items": sorted(
                grouped_items,
                key=lambda k: k[sort_by]
            )
        }
        yield item_group


def split_list(full_list: list, chunk_size: int) -> list:
    """Generate n number of smaller chunks from a list."""
    for i in range(0, len(full_list), chunk_size):
        yield full_list[i:i + chunk_size]


def is_in_the_list(items: list, item:str) -> bool:
    """Check if an items exist in a given list."""
    if item in items:
        response = True
    else:
        response = False

    return response
