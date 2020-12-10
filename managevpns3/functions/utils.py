#!/usr/bin/env python

import re


def stat_inc(dictionary, key):
    """
    Incrament key stat in dictionary by 1
    :param dictionary: dictionary with keys with INT values
    :param key: key to be incremented by 1, or created with 1
    :return: empty
    """
    dictionary[key] = dictionary.get(key, 0) + 1
    return


def re_pick(item_list, regex_str):
    """
    Search list, return list with items that match regex.
    :param item_list: list of items
    :param regex_str: regex string
    :return: list of items in item_list that match regex_str
    """
    # compile regex
    str_search = re.compile(regex_str)
    result = []
    # iterate list
    for item_str in item_list:
        # look for match
        match = str_search.search(item_str)
        # when match, add to return queue
        if match:
            result.append(item_str)
    return result
