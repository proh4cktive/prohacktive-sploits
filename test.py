import os
import sys
import json

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

import phdb
import sourcesmanager
import colors

srcsmanager = sourcesmanager.SourcesManager()
for source in srcsmanager.readSrcsSigs():
    colors.print_info("     Source Name: %s -> %s" % (source["_id"], source["sig"]))