import os
import sys
import json
import datetime

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

import colors
import sourcesmanager
import prohacktivedb

phdb = prohacktivedb.ProHacktiveDB()

#print(phdb.get_references_links_from_exploit_id("NGINX:CORE-2010-0121"))
#print(phdb.get_description_from_exploit_id("NGINX:CORE-2010-0121"))
#print(phdb.search_exploit("NGINX:CORE-2010-0121"))
print(phdb.search_exploits_id_by_software("windows"))
#print(phdb.get_references_id_from_exploit_id("NGINX:CVE-2016-4450"))
#print(phdb.search_exploits_id_by_published_date('2019-01-01T10:00:00', '2019-01-01T11:11:11'))
#print(phdb.search_exploits_id_by_modified_date('2019-01-01T10:00:00', '2019-01-01T11:11:11'))
#print(phdb.search_exploits_id_by_lastseen_date('2019-01-01T10:00:00', '2019-01-01T11:11:11'))
