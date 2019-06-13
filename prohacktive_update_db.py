from datetime import datetime
import os
import sys
import json

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

import config
import colors
import prohacktivedb
import processes
import sourcehelper
from sourcesmanager import SourcesManager


def source_update(src_name):
    # Need new connection for the new process
    phdb = prohacktivedb.ProHacktiveDB()

    # Read local sources signatures
    source_local_sig = sourcehelper.read_source_sig(src_name).decode("utf8")
    source_remote_sig = phdb.find_src_sig_from_name(src_name)

    if source_local_sig == source_remote_sig:
        colors.print_info("[-] Same file signature on %s (%s-%s), skipping" %
                          (src_name, source_local_sig, source_remote_sig))
        return

    # Get time from the top newest update
    update_date_remote = phdb.find_src_dat_from_name(src_name)
    update_date_remote = datetime.strptime(
        update_date_remote, "%Y-%m-%dT%H:%M:%S")

    # Find first the top newest updates on local
    # Read source data
    source_data = json.loads(sourcehelper.read_source(src_name).decode("utf8"))

    exploits_to_update = list()

    for exploit in source_data:
        exploit_lastseen_date = exploit["_source"]["lastseen"]
        exploit_published_date = exploit["_source"]["published"]
        exploit_modified_date = exploit["_source"]["modified"]
        # Get the max date between all those dates
        exploit_update_date = max(
            exploit_lastseen_date, exploit_modified_date, exploit_published_date)
        # If the date is higher than the last source fetching date on remote,
        # we append the exploits we need to update/insert
        exploit_date_local = datetime.strptime(
            exploit_update_date, "%Y-%m-%dT%H:%M:%S")
        if exploit_date_local > update_date_remote:
            exploits_to_update.append(exploit)

    if len(exploits_to_update) == 0:
        raise Exception(
            "File signature has changed but no exploits to update found")

    # Update all exploits into the list
    for exploit in exploits_to_update:
        phdb.update_exploit(exploit, src_name)

    phdb.update_src_sig(src_name, source_local_sig)
    colors.print_success("[x] Updated %s" % src_name)


colors.print_info("[-] ProHacktive updating running...")

srcs_name = SourcesManager().list_all()

phdb = prohacktivedb.ProHacktiveDB()

if len(srcs_name) == 0:
    colors.print_warn("[-] No sources to update!")
else:
    colors.print_warn(
        "[-] updating on host %s with port %s" %
        (phdb.host, phdb.port))

    colors.print_info("[-] Updating sources")

    processes_list = list()

    # Prepare processes for each sources
    for src_name in srcs_name:
        processes_list.append(
            processes.CProcess(
                src_name,
                source_update,
                src_name))

    process_limit_update = config.current_config.process_limit_update

    # Process sources updating
    processes.handle_processes(processes_list, process_limit_update, 0.01)

    colors.print_success(
        "[x] ProHacktive database has been updated successfully!")
