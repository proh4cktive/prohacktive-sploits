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
# On lines we want 

def fetch_handler():
    source_name = "CVESearch"
    colors.print_info("[-] Downloading %s" % source_name)
    source = sourcehelper.SourceHelper(
        "https://cve.circl.lu/static/circl-cve-search-expanded.json.gz")
    source_data = source.fetch()
    # Reformat document
    # sourcehelper.write_source(source_name, source_data)
    # TODO: Reconvert data to Vulners JSON model
    source_data = json.loads(source_data.decode("utf8")).encode("utf8")
    colors.print_success("Saving source %s" % source_name)
    sourcehelper.write_source(source_name, source_data)
    sourcehelper.write_source_sig(
        source_name, sourcehelper.make_sig(source_data))

# fetch_handler()