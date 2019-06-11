import os
import sys
import json

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

import colors
import sourcehelper

source_cve = sourcehelper.read_file_bytes("tmp/fetched_srcs/Vulners_cve")

source_cve = json.loads(source_cve.decode("utf8"))

print("Done %s" % source_cve[0]["_id"])