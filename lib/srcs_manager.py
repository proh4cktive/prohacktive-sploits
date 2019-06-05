import os
import sys
import re
import json
from threading import Thread
from threading import Event
import time

srcs_dir = "srcs/"
runPath = os.path.dirname(os.path.realpath(__file__ + "../../"))
sys.path.append(runPath + "/" + srcs_dir)

import ph_db
import colors
import config
import src_helper


def getFetchedSrcsDir():
    return src_helper.getFetchedSrcsDir()


if not os.path.exists(getFetchedSrcsDir()):
    os.mkdir(getFetchedSrcsDir())


def mergeDicts(dict1, dict2):
    res = {**dict1, **dict2}
    return res


class SrcModule():
    def __init__(self, name, path, module):
        self.path = path
        self.module = module
        self.name = name

# Changing to multiprocessing might be a good idea...
class CSourceThread(Thread):
    def __init__(self, module, name, function_name):
        Thread.__init__(self)
        self.module = module
        self.name = name
        self.function_name = function_name
        self.event = Event()
        self.terminated = False

    def run(self):
        # Get function from module
        fetch_func = getattr(self.module, self.function_name)
        # If it's present load it
        if fetch_func:
                # Fetch data from the source
            colors.print_warn("[-] Loading source %s" % self.name)
            fetch_func()
            colors.print_success("[x] Loaded source %s" % self.name)
        else:
            colors.print_error(
                "[!] fetch_handler function isn't avaiable on module %s" %
                self.name)
        self.event.set()
        self.terminated = True


class SourcesManager():
    def __init__(self):
        # Name of the function that will be called when the module will be
        # loaded
        self.str_fetch_func = "fetch_handler"
        self.src_sigs = list()

    def fetchAll(self):
        # Init sources
        srcs = list()
        # Get path of all sources
        path = os.path.join(runPath, srcs_dir)
        # Import all Source_*.py modules
        for f in os.listdir(path):
            if os.path.isfile(srcs_dir + f):
                # Start with sources and end with py
                pattern_start = r"^Source_"
                pattern_end = r"\.py$"
                if re.findall(pattern_start, f) and re.findall(pattern_end, f):
                    colors.print_warn("[-] Importing source %s" % f[7:-3])
                    module = __import__(f[:-3])
                    if not module:
                        colors.print_error("[!] Couldn't load %s" % f)
                        return 0
                    else:
                        srcs.append(SrcModule(
                            f[7: -3],
                            runPath + "/" + srcs_dir + f,
                            module))
        # For each sources call the source handler to fetch data in multiples threads
        # TODO: Add thread limit aswell for fetching sources in configuration file
        thread_limit = config.current_config.thread_limit_fetch
        count_threads = 0
        thread_count_limit = len(srcs)
        threads = list()
        colors.print_warn("[-] Starting %i threads with sources:" % thread_limit)

        while True:
            # Start x threads by x threads by default
            threads_len = len(threads)
            if threads_len < thread_limit and count_threads < thread_count_limit:
                colors.print_info(srcs[count_threads].name)
                collection_thread = CSourceThread(
                    srcs[count_threads].module, srcs[count_threads].name, self.str_fetch_func)
                collection_thread.start()
                threads.append(collection_thread)
                count_threads += 1
            else:
                # Wait for the threads terminating
                for thread in threads:
                    # Can't use wait() here
                    if thread.terminated:
                        threads.remove(thread)
                    # Sleep 1 millisecond for cpu usage
                    time.sleep(0.001)
                if len(threads) == 0:
                    break
        return 1

    def listAll(self):
        srcs = list()
        # List all files who have changed
        for f in os.listdir(getFetchedSrcsDir()):
            if f.endswith(".dat") or f.endswith(".sig"):
                continue
            if os.path.isfile(getFetchedSrcsDir() + f):
                colors.print_info("[-] Found source to update %s" % f)
                srcs.append(f)
        return srcs

    def readSrcsSigs(self):
        self.src_sigs = list()
        for f in os.listdir(getFetchedSrcsDir()):
            if os.path.isfile(getFetchedSrcsDir() + f + ".sig"):
                filename_sig = open(getFetchedSrcsDir() + f + ".sig", "rb")
                signature = filename_sig.read()
                filename_sig.close()
                self.src_sigs.append({"_id": f, "sig": signature})
        return self.src_sigs

    def findSrcNameFromSig(self, sig):
        for src_sig in self.src_sigs:
            if src_sig["sig"] == sig:
                return src_sig["_id"]
        return None

    def findSrcSigFromName(self, name):
        for src_sig in self.src_sigs:
            if src_sig["_id"] == name:
                return src_sig["sig"]
        return None
