import os
import sys
import json

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

from srcs_manager import SourcesManager
import colors
import ph_db

colors.print_info("[-] ProHacktive fetching running...")

srcsmanager = SourcesManager()
if srcsmanager.fetchAll():
    colors.print_info("[-] Sources generated signatures:")
    for source in srcsmanager.readSrcsSigs():
        colors.print_info("     Source Name: %s -> %s" % (source["_id"], source["sig"]))
    colors.print_success("[x] ProHacktive fetching done!")
else:
    colors.print_error("[!] ProHacktive fetching failed")