# -*- coding: utf-8 -*-
"""Class to handle python arrays."""

import sys
from logging import getLogger
from os import get_terminal_size
from itertools import groupby

MODULE_LOGGER = getLogger(__name__)


class ListToColumns:
    """Display a list of items in a variable # of columns depending on the
    terminal width."""
    _class_logger = MODULE_LOGGER.getChild(__qualname__)

    def __init__(self, items: list, col_width: int) -> None:
        """Class constructor."""
        self._instance_logger = self._class_logger.getChild(str(id(self)))
        (ter_width, ter_height) = get_terminal_size()
        self.columns = int(ter_width / col_width)
        if self.columns == 0:
            self._instance_logger.error("Terminal is too small to display the output")
            sys.exit(-1)

        self.items = items
        self.lst_length = len(items)
        self.rows = ter_height

        self.column_length = int(self.lst_length / self.columns)
        if self.column_length * self.columns < self.lst_length:
            self.column_length += 1

    def display(self):
        """Display as many columns as per terminal width."""
        for row in range(self.column_length):
            line = self.items[row]
            for column in range(1, self.columns):
                try:
                    line += f"{self.items[row + column * self.column_length]}"
                except IndexError:
                    continue

            print(line)

    def display_one_column(self):
        """Display all items of the array in a single columns."""
        for row in self.items:
            print(row)


class GetItemFrom:
    """Get item from array."""
    def __init__(self, items: list) -> None:
        """Class constructor."""
        self.items = items

    def by_key_pair(self, key: str, value: str) -> dict:
        """Get dictionary from an array by a given key."""
        return next((item for item in self.items if item[key] == value), None)

    def values_by_key(self, key: str) -> list:
        """Get an array of values from a single dictionary key."""
        return [item[key] for item in self.items]

    def sorted_values_by_key(self, key: str) -> list:
        """Generate a sorted list of values of an specific key from a list of
        dictionaries."""
        return sorted([item[key] for item in self.items])

    def sorted_items(self, key: str) -> list:
        """Sort a list of dictionaries by a key."""
        return sorted(self.items, key=lambda k: k[key])

    def grouped_items(self, group_by: str, sort_by: str) -> any:
        """Generate a list of dictionaries grouped and sorted by specific
        keys."""
        sorted_list = self.sorted_items(self.items, group_by)  # pylint: disable=E1121
        for group_key, grouped_items in groupby(sorted_list, key=lambda k: k[group_by]):
            item_group = {
                "grouped_by": group_key,
                "grouped_items": sorted(grouped_items, key=lambda k: k[sort_by])
            }
            yield item_group

    def items_in_chunks(self, chunk_size: int) -> any:
        """Generate N number of smaller chunks from a list."""
        for i in range(0, len(self.items), chunk_size):
            yield self.items[i:i + chunk_size]

    def remove_item(self, item: str) -> bool:
        """Remove item from an array."""
        search = bool(item in self.items)
        if search:
            self.items.remove(item)

        return search

    def in_the_list(self, item: str) -> bool:
        """Check if an item exist in a given list."""
        return bool(item in self.items)

    def by_tag_key(self, key: str) -> str:
        """Get tag value from Tags list."""
        tag_item = next((item for item in self.items if item['Key'] == key), None)
        if tag_item:
            tag_value = tag_item['Value']
        else:
            tag_value = None

        return tag_value
