import os
import sys
import json

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

import colors

dict_count = 0
pbar = None
warning_list = "WARNING!!! It is represented as a list but it is for showing the multiples data type here!"


def analyze_list(value, list_parent):
    global dict_count
    global pbar
    for o in value:
        if isinstance(o, dict):
            dict_count += 1
            pbar.update(dict_count)
            dict_keys_child = dict()
            _make_dictionary_of_keys(o, dict_keys_child)

            if len(list_parent) != 0:
                if warning_list in list_parent[0]:
                    unique_list = list()
                    unique_list.append(warning_list)
                    unique_list.append(dict_keys_child)
                    # Traverse for all elements
                    for x in list_parent:
                        # Check if exists in unique_list or not
                        if x not in unique_list:
                            unique_list.append(x)
                    # Seems like there was only one type
                    if len(unique_list) == 2:
                        list_parent = unique_list[1]
                    else:
                        list_parent = unique_list
                else:
                    if dict_keys_child not in list_parent:
                        copy = list_parent
                        list_parent = list()
                        list_parent.append(warning_list)
                        list_parent.append(copy)
                        list_parent.append(dict_keys_child)
            else:
                list_parent.append(dict_keys_child)

        elif isinstance(o, list):
            # If it's a list, we gotta analyze more, no worries
            l = list()
            analyze_list(o, l)
            list_parent.append(l)
        else:
            matched = False
            # Don't insert the same type of data again into our list
            for i in range(len(list_parent)):
                if isinstance(list_parent[i], str):
                    str_type = str(type(o))
                    if(str_type == list_parent[i]):
                        matched = True
                        break
            if not matched:
                list_parent.append(str(type(o)))


# Make a dictionary of keys inside a dictionary wich contains different
# types of values
def _make_dictionary_of_keys(obj, json_keys):
    global dict_count
    global pbar
    # Find keys inside the object
    keys = obj.keys()
    # If there is no keys return
    if not keys:
        return
    # For each keys find new dictionary otherwhise make an array of what kind
    # of types of values we can use for the key
    for key in keys:
        # Get value from key
        value = obj[key]
        # List recursively all dicts inside the value if it's a dict
        if isinstance(value, dict):
            if not json_keys.get(key):
                json_keys[key] = dict()
            _make_dictionary_of_keys(value, json_keys[key])
            dict_count += 1
            pbar.update(dict_count)
        # If the value is a list
        elif isinstance(value, list):
            if len(value) != 0:
                if not json_keys.get(key):
                    json_keys[key] = list()
                    # Analyze the list
                    analyze_list(value, json_keys[key])
                # Should never happen
                else:
                    final_list = list()
                    analyze_list(value, final_list)
                    if warning_list in json_keys[key][0]:
                        unique_list = list()
                        unique_list.append(warning_list)
                        unique_list.append(final_list)
                        # Traverse for all elements
                        for x in json_keys[key]:
                            # Check if exists in unique_list or not
                            if x not in unique_list:
                                unique_list.append(x)
                        # Seems like there was only one type
                        if len(unique_list) == 2:
                            json_keys[key] = unique_list[1]
                        else:
                            json_keys[key] = unique_list
                    else:
                        copy = json_keys[key]
                        # If it's not equal it means that the list is different
                        # From the new one
                        if final_list != copy:
                            json_keys[key] = list()
                            json_keys[key].append(warning_list)
                            json_keys[key].append(copy)
                            json_keys[key].append(final_list)
            else:
                empty_list = "empty list"
                if not json_keys.get(key):
                    json_keys[key] = empty_list
                else:
                    if warning_list in json_keys[key][0]:
                        unique_list = list()
                        unique_list.append(warning_list)
                        unique_list.append(empty_list)
                        # Traverse for all elements
                        for x in json_keys[key]:
                            # Check if exists in unique_list or not
                            if x not in unique_list:
                                unique_list.append(x)
                        # Seems like there was only one type
                        if len(unique_list) == 2:
                            json_keys[key] = unique_list[1]
                        else:
                            json_keys[key] = unique_list
                    else:
                        copy = json_keys[key]
                        # If it's not equal it means that the list is different
                        # From the new one
                        if empty_list != copy:
                            json_keys[key] = list()
                            json_keys[key].append(warning_list)
                            json_keys[key].append(copy)
                            json_keys[key].append(empty_list)
        else:
            # Maybe there is multiples data type for one field?
            # Should never happen
            if json_keys.get(key):
                # If it's not a list, then we check if the value
                # isn't the same as the other value in the field
                if json_keys[key] != str(type(value)):
                    if warning_list in json_keys[key][0]:
                        unique_list = list()
                        unique_list.append(warning_list)
                        unique_list.append(str(type(value)))
                        # Traverse for all elements
                        for x in json_keys[key]:
                            # Check if exists in unique_list or not
                            if x not in unique_list:
                                unique_list.append(x)
                        # Seems like there was only one type
                        if len(unique_list) == 2:
                            json_keys[key] = unique_list[1]
                        else:
                            json_keys[key] = unique_list
                    else:
                        copy = json_keys[key]
                        json_keys[key] = list()
                        json_keys[key].append(warning_list)
                        json_keys[key].append(copy)
                        json_keys[key].append(str(type(value)))

            else:  # First data type
                json_keys[key] = str(type(value))


def make_dictionary_of_keys(obj):
    # If it's just a dictionary start directly from there
    if isinstance(obj, dict):
        json_keys = dict()
        _make_dictionary_of_keys(obj, json_keys)
    # Otherwhise it must be a list of dicts
    else:
        json_keys = dict()
        for o in obj:
            # Dictionary of keys
            _make_dictionary_of_keys(o, json_keys)
        """json_keys = set()
        for o in obj:
            # Dictionary of keys
            json_keys_childs = dict()
            _make_dictionary_of_keys(o, json_keys_childs)
            # Do not duplicate
            json_keys.add(json.dumps(json_keys_childs, sort_keys=True))
        # Copy json data and convert it to dicts again
        copies = json_keys
        json_keys = list()
        for copy in copies:
            json_keys.append(json.loads(copy))"""

    return json_keys


def count_from_list_dicts(value):
    global dict_count
    for o in value:
        if isinstance(o, dict):
            dict_count += 1
            _count_dicts(o)
        elif isinstance(o, list):
            count_from_list_dicts(o)


def _count_dicts(json_obj):
    global dict_count
    keys = json_obj.keys()
    if not keys:
        return
    for key in keys:
        value = json_obj[key]
        if isinstance(value, dict):
            dict_count += 1
            _count_dicts(value)
        elif isinstance(value, list):
            count_from_list_dicts(value)


def count_dicts(json_obj):
    # If dictionary start directly from there
    if isinstance(json_obj, dict):
        _count_dicts(json_obj)
    # Otherwhise it must be a list
    else:
        for o in json_obj:
            _count_dicts(o)


# Check if argument is passed
sys.argv.append("test.json")
if sys.argv[1]:

    # Read json data
    colors.print_info("[-] Loading %s" % sys.argv[1])
    json_file = open(sys.argv[1], "r")
    json_data = json.loads(json_file.read())
    json_file.close()

    colors.print_info("[-] Counting dictionaries...")

    dict_count = 0

    # Count all dictionaries
    count_dicts(json_data)

    pbar = colors.print_progress_start(dict_count)

    colors.print_info("[-] Analyzing %i dictionaries..." % dict_count)

    # Reset counter
    dict_count = 0

    # For each objects find
    json_keys = make_dictionary_of_keys(json_data)

    pbar.finish()

    colors.print_success("")

    # There's multiples possibilities because sometimes keyvalues store
    # different data types
    """if isinstance(json_keys, list):
        list_number = 1
        for jk in json_keys:
            colors.print_info("--- Possibility %i ----"%list_number)
            colors.print_success((json.dumps(jk, sort_keys=True, indent=4)))
            list_number += 1
    else:"""
    colors.print_success((json.dumps(json_keys, sort_keys=True, indent=4)))

    colors.print_success("")
    colors.print_success("[x] The json file has been successfully analyzed!")
