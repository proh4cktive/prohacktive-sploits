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
result = phdb.search_vulnerabilities_id(vulnerability_id="CVE-2019-06.", collection_name="Vulners_cve",
                                        max_modified_date="2019-06-14T00:00:00", min_modified_date="2019-06-01T00:00:00")
for cve_id in result:
    print(json.dumps(phdb.get_vulnerability_info(
        cve_id, collection_name="Vulners_cve"), indent=4, sort_keys=True))
