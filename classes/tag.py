# -*- coding: utf-8 -*-
"""Class to handle resource tags."""

def _curated_str(string: str) -> str:
    """Remove CSV file conflictive characters from string."""
    return string.replace('\"', '').replace('\'', '').replace(',', ';')


class Tag:
    """Handle tags."""

    def __init__(self, tags: list) -> None:
        """Define class variables."""
        self.tags = tags

    def get_all_tags(self) -> dict:
        """Get all tags in a dictionary."""
        tags_dict = dict()
        if self.tags:
            for t in self.tags:
                tags_dict[t['Key']] = t['Value']

        return tags_dict

    def get_all_tags_curated(self) -> dict:
        """Get all tags in a dictionary."""
        tags_dict = dict()
        if self.tags:
            for t in self.tags:
                tags_dict[t['Key']] = _curated_str(t['Value'])

        return tags_dict

    def get_tags_of_interest_OLD(self, tags_of_interest: dict) -> dict:
        """Get tags of insterest in a dictionary."""
        if self.tags:
            for t in self.tags:
                if t['Key'] in tags_of_interest.keys():
                    tags_of_interest[t['Key']] = _curated_str(t['Value'])

        return tags_of_interest

    def get_tags_of_interest(self, default_tags: dict) -> dict:
        """Get tags of insterest in a dictionary."""
        if self.tags:
            tags_of_interest = dict()
            tag_dict = self.get_all_tags_curated()
            for k in default_tags.keys():
                if k in tag_dict.keys():
                    tags_of_interest[k] = _curated_str(tag_dict[k])
                else:
                    tags_of_interest[k] = "NoValue"
        else:
            tags_of_interest = default_tags

        return tags_of_interest

    def values(self, default_tags: dict) -> list:
        """Get tag key names."""
        tags = self.get_tags_of_interest(default_tags)
        values = list(tags.values())
        values.append(values.count('NoValue'))
        return values

    def keys(self, default_tags: dict) -> list:
        """Get tag key names."""
        tags = self.get_tags_of_interest(default_tags)
        keys = list(tags.keys())
        keys.append('CountMissedTag')
        return keys
