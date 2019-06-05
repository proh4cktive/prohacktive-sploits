import os
import sys
import vulners
import json
import time
from zipfile import ZipFile
from threading import Thread
from threading import Event

runPath = os.path.dirname(os.path.realpath(__file__ + "../../"))
sys.path.append(runPath + "/lib/")

import config
import colors
import srcs_manager
import src_helper
from datetime import datetime
from io import BytesIO

vulners_api_key = config.current_config.vulners_api_key

fetched_srcs = srcs_manager.getFetchedSrcsDir()

# This function will get called by the main python file


class CCollectionThread(Thread):
    def __init__(self, collection_name, vulners_api, datefrom='1950-01-01', dateto='2199-01-01'):
        Thread.__init__(self)
        self.collection_name = collection_name
        self.collection = None
        self.vulners_api = vulners_api
        self.datefrom = datefrom
        self.dateto = dateto
        self.event = Event()
        # Set cleared event
        self.event.clear()

    def run(self):
        time = datetime.now()
        time = "%i-%i-%iT%i-%i-%i" % (time.year, time.month, time.day,
                                      time.hour, time.minute, time.second)

        colors.print_info("[-] Downloading %s in %s" %
                          (self.collection_name, self.getName()))

        collection = self.vulners_api.vulners_get_request(
            'archive', {'type': self.collection_name, 'datefrom': self.datefrom, 'dateto': self.dateto})

        # Decompress zip data
        with ZipFile(BytesIO(collection)) as zip_file:
            if len(zip_file.namelist()) > 1:
                raise Exception("Unexpected file count in Vulners ZIP archive")
            file_name = zip_file.namelist()[0]
            collection = bytearray(zip_file.open(file_name).read())

        collection_name = "Vulners_" + self.collection_name

        src_sig = src_helper.makeSig(collection)

        src_read_sig = src_helper.readSourceSig(collection_name)

        collection_file_data = collection_name + ".dat"

        # Check if we need to write the file
        if (os.path.exists(fetched_srcs + collection_file_data)
            and os.path.exists(fetched_srcs + collection_name + ".sig")
            and os.path.exists(fetched_srcs + collection_name)
                and src_sig == src_read_sig):
            colors.print_info(
                "[-] Skipped writing to file the source %s, signature didn't change" % collection_name)
            # Still overwrite the date
            src_helper.writeFileBytes(
                fetched_srcs + collection_file_data, bytearray(time.encode("ascii")))
        else:
            # Write collection date, could be, maybe used for faster updates in future by using the API
            src_helper.writeFileBytes(
                fetched_srcs + collection_file_data, bytearray(time.encode("ascii")))
            colors.print_info("[-] Saving file signature %s" %
                              (fetched_srcs + collection_name + ".sig"))

            # Write file signature
            src_helper.writeSourceSig(collection_name, src_sig)

            colors.print_info(
                "[-] Saving source %s" %
                (fetched_srcs + collection_name))

            src_helper.writeFileBytes(
                fetched_srcs + collection_name, collection)
        # Thread done
        self.event.set()

# Multithreading fetch


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
    count_threads = 0

    # Let's limit x threads, it's good enough
    while True:
        # Hourra stop there!
        if count_threads >= len(collections):
            break
        # *cries* Sadly the API limits by one download only
        # and must gets replaced by fake multithreading. RIP.
        collection_thread = CCollectionThread(
            collections[count_threads], vulners_api)
        collection_thread.start()
        collection_thread.event.wait()
        count_threads += 1
