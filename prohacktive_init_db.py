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

colors.print_info("[-] ProHacktive full updating running...")

srcs_name = SourcesManager().list_all()


def source_update(src_name):
    # Need new connection for the new process
    phdb = prohacktivedb.ProHacktiveDB()
    src_sig = sourcehelper.read_source_sig(src_name).decode("utf8")
    src_dat = sourcehelper.read_file_bytes(
        sourcehelper.get_fetched_srcs_dir() + src_name + ".dat").decode("utf8")

    colors.print_info("[-] Inserting source %s signature %s" %
                      (src_name, src_sig))

    phdb.insert_src_sig(src_name, src_sig)

    colors.print_info("[-] Inserting source %s dat %s" %
                      (src_name, src_dat))

    phdb.insert_src_dat(src_name, src_dat)

    colors.print_info("[-] Inserting source %s" % src_name)
    src_data = json.loads(sourcehelper.read_source(src_name))

    colors.print_info("[-] Erasing old exploits %s ..." % src_name)
    phdb.collections.drop_collection(src_name)

    colors.print_info("[-] Inserting exploits of %s ..." % src_name)

    phdb.insert_exploits(src_data, src_name)

    colors.print_success("[x] Updated %s" % src_name)


def main():
    phdb = prohacktivedb.ProHacktiveDB()

    if len(srcs_name) == 0:
        colors.print_warn("[-] No sources to update!")
    else:
        colors.print_warn(
            "[-] Full updating on host %s with port %s" %
            (phdb.host, phdb.port))

        colors.print_info("[-] Erasing old signatures")
        phdb.collections.drop_collection(phdb.get_srcs_sigs_collection_name())

        colors.print_info("[-] Erasing old data informations")
        phdb.collections.drop_collection(phdb.get_srcs_dat_collection_name())

        colors.print_info("[-] Erasing old statistics")
        phdb.drop_remote_stats()

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
            "[x] ProHacktive database has been full updated successfully!")


main()
