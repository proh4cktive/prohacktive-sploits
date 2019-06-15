import os
import sys
import json
import time
import requests

runPath = os.path.dirname(os.path.realpath(__file__ + "../../"))
sys.path.append(runPath + "/lib/")

import config
import colors
import sourcehelper

# http://cve-search.org/dataset/
# Their JSON data are fucked up but it can be fixed by adding , at every lines and adding []
# at the start & end of line


def fetch_handler():
    source_name = "CVESearch"
    colors.print_info("[-] Downloading %s" % source_name)
    source = sourcehelper.SourceHelper(
        "https://cve.circl.lu/static/circl-cve-search-expanded.json.gz")
    source_data = source.fetch()
    source_data = source_data.decode("utf8")
    source_data = source_data.replace("\n", ",\n")
    source_data = "[" + source_data
    source_data = source_data[:-2] + "]\n"
    # Reformat document
    # sourcehelper.write_source(source_name, source_data)
    # TODO: Reconvert data to Vulners JSON model
    source_data = json.dumps(json.loads(source_data))
    colors.print_success("Saving  source %s" % source_name)
    sourcehelper.write_source(source_name, source_data)
    sourcehelper.write_source_sig(
        source_name, sourcehelper.make_sig(source_data))

fetch_handler()
