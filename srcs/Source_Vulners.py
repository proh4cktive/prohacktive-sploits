import os
import sys
import vulners
import json
import time
from zipfile import ZipFile

runPath = os.path.dirname(os.path.realpath(__file__ + "../../"))
sys.path.append(runPath + "/lib/")

import config
import colors
import processes
import sourcesmanager
import sourcehelper
from datetime import datetime
from io import BytesIO

vulners_api_key = config.current_config.vulners_api_key

fetched_srcs = sourcesmanager.get_fetched_srcs_dir()


def vulners_source_fetch(api_key, collection_name):
    source_name = "Vulners_" + collection_name
    source_file_data = source_name + ".dat"
    source_file_sig = source_name + ".sig"
    datetime_now = datetime.now()
    time_fmt = datetime_now.strftime("%Y-%m-%dT%H:%M:%S")
    important_files_exists = (os.path.isfile(fetched_srcs + source_name)
                              and os.path.isfile(fetched_srcs + source_file_sig)
                              and os.path.isfile(fetched_srcs + source_file_data))

    if important_files_exists:
        read_source_date = sourcehelper.read_file(
            fetched_srcs + source_file_data)
        from_date = str(read_source_date)
        to_date = time_fmt

        colors.print_info("[-] Downloading %s from date %s to date %s" %
                          (collection_name, from_date, to_date))

        vulners_api = vulners.Vulners(api_key)
        source_update = vulners_api.vulners_get_request(
            'archive', {'type': collection_name, 'datefrom': from_date})

        # Decompress zip data
        with ZipFile(BytesIO(source_update)) as zip_file:
            if len(zip_file.namelist()) > 1:
                raise Exception("Unexpected file count in Vulners ZIP archive")
            file_name = zip_file.namelist()[0]
            source_update = bytes(zip_file.open(file_name).read())

        source_update = json.loads(source_update.decode("utf8"))
        
        # No updates
        if len(source_update) == 0:
            colors.print_info("[-] No updates on %s, skipping" % source_name)
            sourcehelper.write_file(fetched_srcs + source_file_data, to_date)
            return
        
        source_data = sourcehelper.read_source(source_name).decode("utf8")
        source_data = json.loads(source_data)

        # Find every exploits that needs update into the file and update it
        for exploit_index in range(len(source_data)):
            for exploit_update in source_update:
                if source_data[exploit_index]["_id"] == exploit_update["_id"]:
                    source_data[exploit_index]["_id"] = exploit_update["_id"]

        colors.print_info("[-] Saving file signature %s" %
                          (fetched_srcs + source_file_sig))

        # Re-encode data
        source_data = bytes(json.dumps(source_data).encode("utf8"))

        # Write file signature
        sourcehelper.write_source_sig(
            source_name, sourcehelper.make_sig(source_data))

        # Write file date (we might use the date directly from the os but to be sure)
        sourcehelper.write_file(fetched_srcs + source_file_data, to_date)

        colors.print_info(
            "[-] Saving source %s" %
            (fetched_srcs + source_name))

        sourcehelper.write_source(source_name, source_data)

    else:

        colors.print_info("[-] Downloading %s" % source_name)
        vulners_api = vulners.Vulners(api_key)
        collection = vulners_api.vulners_get_request(
            'archive', {'type': collection_name})

        # Decompress zip data
        with ZipFile(BytesIO(collection)) as zip_file:
            if len(zip_file.namelist()) > 1:
                raise Exception("Unexpected file count in Vulners ZIP archive")
            file_name = zip_file.namelist()[0]
            # Reformat document with a json load so it writes correct signature & convert it to bytes
            collection = bytes(json.dumps(json.loads(zip_file.open(
                file_name).read().decode("utf8"))).encode("utf8"))

        src_sig = sourcehelper.make_sig(collection)

        # Write collection date, used for faster updates by using the API
        sourcehelper.write_file(fetched_srcs + source_file_data, time_fmt)
        colors.print_info("[-] Saving file signature %s" %
                          (fetched_srcs + source_file_sig))

        # Write file signature
        sourcehelper.write_source_sig(source_name, src_sig)

        colors.print_info(
            "[-] Saving source %s" %
            (fetched_srcs + source_name))

        sourcehelper.write_source(source_name, collection)


def fetch_handler():
    vulners_api = vulners.Vulners(vulners_api_key)
    colors.print_info(
        "[-] Vulners API loading multiples collections:\n")

    count_for_newline = 0
    print_new_line = False

    collections = vulners_api.collections()
    number_of_collections = len(collections)

    for collection_name in collections:
        if (count_for_newline > 0) and ((count_for_newline % 6) == 0):
            print("\n", end="")
            print_new_line = False

        if count_for_newline == (number_of_collections - 1):
            print(collection_name, end="")
        else:
            print(collection_name + ", ", end="")

        count_for_newline += 1
        print_new_line = True

    if print_new_line:
        print("\n")

    colors.print_warn("[-] Downloading %i sub-sources..." % len(collections))

    processes_list = list()
    for collection_name in collections:
        processes_list.append(processes.CProcess(
            collection_name, vulners_source_fetch, vulners_api_key, collection_name))

    processes_count_limit = len(processes_list)
    processes.handle_processes(processes_list, processes_count_limit, 0.01)
