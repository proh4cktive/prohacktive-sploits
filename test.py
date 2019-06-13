import os
import sys
import json

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

import colors
import sourcehelper



if sourcehelper.is_file_compressed("tmp/fetched_srcs/CVESearch"):
    print("Done")