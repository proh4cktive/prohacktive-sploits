import os
import sys
import vulners
import json
import time
from zipfile import ZipFile
import processes

runPath = os.path.dirname(os.path.realpath(__file__ + "../../"))
sys.path.append(runPath + "/lib/")

import config
import colors
import sourcesmanager
import sourcehelper
from datetime import datetime
from io import BytesIO

vulners_api_key = config.current_config.vulners_api_key

fetched_srcs = sourcesmanager.get_fetched_srcs_dir()


def vulners_source_fetch(api_key, collection_name, datefrom="1950-01-01", dateto="2200-01-01"):
    time = datetime.now()
    time = "%i-%i-%iT%i-%i-%i" % (time.year, time.month, time.day,
                                  time.hour, time.minute, time.second)

    colors.print_info("[-] Downloading %s " % collection_name)
    vulners_api = vulners.Vulners(api_key)
    collection = vulners_api.vulners_get_request(
        'archive', {'type': collection_name})  # , 'datefrom': datefrom, 'dateto': dateto})

    # Decompress zip data
    with ZipFile(BytesIO(collection)) as zip_file:
        if len(zip_file.namelist()) > 1:
            raise Exception("Unexpected file count in Vulners ZIP archive")
        file_name = zip_file.namelist()[0]
        collection = bytearray(zip_file.open(file_name).read())

    collection_name = "Vulners_" + collection_name

    src_sig = sourcehelper.make_sig(collection)

    src_read_sig = sourcehelper.read_source_sig(collection_name)

    collection_file_data = collection_name + ".dat"

    # Check if we need to write the file
    if (os.path.exists(fetched_srcs + collection_file_data)
        and os.path.exists(fetched_srcs + collection_name + ".sig")
        and os.path.exists(fetched_srcs + collection_name)
            and src_sig == src_read_sig):
        colors.print_info(
            "[-] Skipped writing to file the source %s, signature didn't change" % collection_name)
        # Still overwrite the date
        sourcehelper.write_file_bytes(
            fetched_srcs + collection_file_data, bytearray(time.encode("ascii")))
    else:
        # Write collection date, could be, maybe used for faster updates in future by using the API
        sourcehelper.write_file_bytes(
            fetched_srcs + collection_file_data, bytearray(time.encode("ascii")))
        colors.print_info("[-] Saving file signature %s" %
                          (fetched_srcs + collection_name + ".sig"))

        # Write file signature
        sourcehelper.write_source_sig(collection_name, src_sig)

        colors.print_info(
            "[-] Saving source %s" %
            (fetched_srcs + collection_name))

        sourcehelper.write_file_bytes(
            fetched_srcs + collection_name, collection)


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
