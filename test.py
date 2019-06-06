import os
import sys
import json

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

import colors
import sourcesmanager

srcsmanager = sourcesmanager.SourcesManager()
for source in srcsmanager.read_srcs_sigs():
    colors.print_info("     Source Name: %s -> %s" % (source["_id"], source["sig"]))
