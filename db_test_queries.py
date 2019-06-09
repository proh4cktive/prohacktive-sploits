import os
import sys
import json

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

import colors
import sourcesmanager
import prohacktivedb

phdb = prohacktivedb.ProHacktiveDB()

print(phdb.get_references_links_from_exploit_id("NGINX:CORE-2010-0121"))
print(phdb.get_description_from_exploit_id("NGINX:CORE-2010-0121"))
print(phdb.get_references_from_exploit_id("NGINX:CVE-2016-4450"))