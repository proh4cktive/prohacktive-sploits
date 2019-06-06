import os
import sys
import json
import time

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

import config
import colors
import ph_db
from ph_db import phdb
import processes
import src_helper
from srcs_manager import SourcesManager

colors.print_info("[-] ProHacktive full updating running...")

srcsmanager = SourcesManager()
srcs_name = srcsmanager.listAll()


def sourceUpdate(src_name):
    # Need new connection for the new process
    phdb = ph_db.ProHacktiveDB()
    src_sig = src_helper.readSourceSig(src_name)
    colors.print_info("[-] Inserting source %s signature %s" %
                      (src_name, src_sig))

    phdb.insertSrcSignature(src_name, str(src_sig))

    colors.print_info("[-] Inserting source %s" % src_name)
    src_data = json.loads(src_helper.readSource(src_name))

    colors.print_info("[-] Erasing old exploits %s ..." % src_name)
    phdb.collections.drop_collection(src_name)

    colors.print_info("[-] Inserting exploits of %s ..." % src_name)

    for exploit in src_data:
        phdb.insertExploit(exploit, src_name)

    colors.print_success("[x] Updated %s" % (src_name))


if len(srcs_name) == 0:
    colors.print_warn("[-] No sources to update!")
else:
    colors.print_warn(
        "[-] Full updating on host %s with port %s" %
        (phdb.host, phdb.port))

    colors.print_info("[-] Erasing old signatures")
    phdb.collections.drop_collection(phdb.getSrcSigsCollectionName())

    colors.print_info("[-] Updating sources")

    processes_list = list()

    # Prepare processes for each sources
    for src_name in srcs_name:
        processes_list.append(processes.CProcess(src_name, sourceUpdate, src_name))

    process_limit_update = config.current_config.process_limit_update

    # Process sources updating
    processes.handleProcesses(processes_list, process_limit_update, 0.01)

    colors.print_success(
        "[x] ProHacktive database has been full updated successfully!")
