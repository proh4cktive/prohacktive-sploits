import os
import sys
import re
import json
import processes
import time

srcs_dir = "srcs/"
runPath = os.path.dirname(os.path.realpath(__file__ + "../../"))
sys.path.append(runPath + "/" + srcs_dir)

import colors
import config
import sourcehelper


def get_fetched_srcs_dir():
    return sourcehelper.get_fetched_srcs_dir()


if not os.path.exists(get_fetched_srcs_dir()):
    os.mkdir(get_fetched_srcs_dir())


class SourceModule():
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

    def fetch_source(self, module, module_name):
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

    def fetch_all(self):
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
                        srcs.append(SourceModule(
                            f[7: -3],
                            runPath + "/" + srcs_dir + f,
                            module))

        # Prepare processes
        processes_list = list()
        for src in srcs:
            processes_list.append(processes.CProcess(src.name,
                                                     self.fetch_source, src.module, src.name))

        # Handle processes
        processes_running_limit = config.current_config.process_limit_update
        processes.handle_processes(processes_list, processes_running_limit, 0.01)

        return 1

    def list_all(self):
        srcs = list()
        # List all files who have changed
        for f in os.listdir(get_fetched_srcs_dir()):
            if f.endswith(".dat") or f.endswith(".sig"):
                continue
            if os.path.isfile(get_fetched_srcs_dir() + f):
                srcs.append(f)
        return srcs

    def read_srcs_sigs(self):
        self.src_sigs = list()
        for f in os.listdir(get_fetched_srcs_dir()):
            if os.path.isfile(get_fetched_srcs_dir() + f + ".sig"):
                filename_sig = sourcehelper.read_source_sig(f)
                self.src_sigs.append({"_id": f, "sig": filename_sig})
        return self.src_sigs

    def find_src_name_from_sig(self, sig):
        for src_sig in self.src_sigs:
            if src_sig["sig"] == sig:
                return src_sig["_id"]
        return None

    def find_src_sig_from_name(self, name):
        for src_sig in self.src_sigs:
            if src_sig["_id"] == name:
                return src_sig["sig"]
        return None
