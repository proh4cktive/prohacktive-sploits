import os
import sys
import re
import json
import processes
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


class SourcesManager():
    def __init__(self):
        # Name of the function that will be called when the module will be
        # loaded
        self.str_fetch_func = "fetch_handler"
        self.src_sigs = list()

    def fetchSource(self, module, module_name):
        # Get function from module
        fetch_func = getattr(module, self.str_fetch_func)
        # If it's present load it
        if fetch_func:
            # Fetch data from the source
            colors.print_warn("[-] Loading source %s" % module_name)
            fetch_func()
            colors.print_success("[x] Loaded source %s" % module_name)
        else:
            colors.print_error(
                "[!] fetch_handler function isn't avaiable on module %s" %
                module_name)

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

        # Prepare processes
        processes_list = list()
        for src in srcs:
            processes_list.append(processes.CProcess(src.name,
                self.fetchSource, src.module, src.name))

        # Handle processes
        processes_running_limit = config.current_config.process_limit_update
        processes.handleProcesses(processes_list, processes_running_limit, 0.01)

        return 1

    def listAll(self):
        srcs = list()
        # List all files who have changed
        for f in os.listdir(getFetchedSrcsDir()):
            if f.endswith(".dat") or f.endswith(".sig"):
                continue
            if os.path.isfile(getFetchedSrcsDir() + f):
                srcs.append(f)
        return srcs

    def readSrcsSigs(self):
        self.src_sigs = list()
        for f in os.listdir(getFetchedSrcsDir()):
            if os.path.isfile(getFetchedSrcsDir() + f + ".sig"):
                filename_sig = src_helper.readSourceSig(f)
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
