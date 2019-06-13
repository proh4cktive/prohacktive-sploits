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

colors.print_warn("[-] Testing references")
colors.print_info(str(phdb.get_references_links_from_exploit_id("NGINX:CORE-2010-0121")))
colors.print_warn("[-] Testing descriptions")
colors.print_info(str(phdb.get_description_from_exploit_id("NGINX:CORE-2010-0121")))
colors.print_warn("[-] Testing searching")
colors.print_info(str(phdb.search_exploit("NGINX:CORE-2010-0121")))
colors.print_warn("[-] Testing software")
colors.print_info(str(phdb.search_exploits_id_by_software("apache")))
colors.print_warn("[-] Testing cpe")
colors.print_info(str(phdb.search_exploits_id_by_cpe("cpe:/o:microsoft:windows_server_2012:r2")))
colors.print_warn("[-] Testing cvelist")
colors.print_info(str(phdb.get_cvelist_by_exploit_id("CVE-2016-3319", "Vulners_cve")))
colors.print_warn("[-] Testing references")
colors.print_info(str(phdb.get_references_id_from_exploit_id("NGINX:CVE-2016-4450")))
colors.print_warn("[-] Testing published date")
colors.print_info(str(phdb.search_exploits_id_by_published_date('2019-01-01T10:00:00', '2019-01-01T11:11:11')))
colors.print_warn("[-] Testing modified date")
colors.print_info(str(phdb.search_exploits_id_by_modified_date('2019-01-01T10:00:00', '2019-01-01T11:11:11')))
colors.print_warn("[-] Testing lastseen date")
colors.print_info(str(phdb.search_exploits_id_by_lastseen_date('2019-01-01T10:00:00', '2019-01-01T11:11:11')))
