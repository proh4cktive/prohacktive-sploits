import os
import sys
import json
from threading import Thread
from threading import Event
import time

runPath = os.path.dirname(os.path.realpath(__file__ + "../"))
sys.path.append(runPath + "/lib/")

import config
import colors
import src_helper
from srcs_manager import SourcesManager
from ph_db import phdb

colors.print_info("[-] ProHacktiveDB syncing running...")

srcsmanager = SourcesManager()
srcs = srcsmanager.listAll()

# Changing to multiprocessing could be a good idea...
class SourceUpdateThread(Thread):
    def __init__(self, src_name):
        Thread.__init__(self)
        self.event = Event()
        self.src_name = src_name
        self.terminated = False

    def run(self):
        src_sig = src_helper.readSourceSig(self.src_name)
        colors.print_info("[-] Inserting source %s signature %s" %
                          (self.src_name, src_sig))
        phdb.insertSrcSignature(self.src_name, str(src_sig))

        colors.print_info("[-] Inserting source %s" % self.src_name)
        src_data = json.loads(src_helper.readSource(self.src_name))

        colors.print_info("[-] Erasing old exploits %s ..." % self.src_name)
        phdb.collections.drop_collection(self.src_name)

        colors.print_info("[-] Inserting exploits of %s ..." % self.src_name)

        for exploit in src_data:
            phdb.insertExploit(exploit, self.src_name)

        stats = phdb.getLocalStats(self.src_name)
        colors.print_success(
            "[x] Updated %s with %i updates & %i inserts" %
            (self.src_name, len(stats.exploit_updates),
                len(stats.exploit_inserts)))

        self.event.set()
        self.terminated = True


if len(srcs) == 0:
    colors.print_warn("[-] No sources to update!")
else:
    colors.print_warn(
        "[-] Full updating on host %s with port %s" %
        (phdb.host, phdb.port))

    colors.print_info("[-] Erasing old signatures")
    phdb.collections.drop_collection(phdb.getSrcSigsCollectionName())

    colors.print_info("[-] Erasing remote statistics")
    phdb.eraseRemoteStats()
    phdb.initLocalStats(srcs)

    colors.print_info("[-] Updating sources")

    count_threads = 0
    thread_count_limit = len(srcs)
    # This shit can take a lot of RAM.
    # Use this with caution. (it crashed my computer!)
    # thread_limit = thread_count_limit
    thread_limit = config.current_config.thread_limit_update
    threads = list()

    # Update all sources in multiple threads
    while True:
        threads_len = len(threads)
        # Start x threads by x threads by default
        if threads_len < thread_limit and count_threads < thread_count_limit:
            colors.print_warn(
                "[!] Running thread for source %s" % srcs[count_threads])
            thread = SourceUpdateThread(srcs[count_threads])
            thread.start()
            threads.append(thread)
            count_threads += 1
            # colors.print_info("[-] Currently running:")
            # for thread in threads:
            #    print("     %s" % thread.src_name)
        else:
            # Wait for the threads terminating
            for thread in threads:
                # Can't use wait() there. Because we can't know if the
                # Next thread is terminated
                if thread.terminated:
                    threads.remove(thread)
                # Sleep 1 millisecond for cpu usage
                time.sleep(0.001)

            if len(threads) == 0:
                break

    # Inserting stats
    colors.print_info("[-] Inserting statistics")
    phdb.insertStats()
    colors.print_success(
        "[x] ProHacktive database has been full updated successfully!")
