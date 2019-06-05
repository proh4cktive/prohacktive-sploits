import os
import sys
import json

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

import ph_db
import srcs_manager
import colors

srcsmanager = srcs_manager.SourcesManager()
for source in srcsmanager.readSrcsSigs():
    colors.print_info("     Source Name: %s -> %s" % (source["_id"], source["sig"]))