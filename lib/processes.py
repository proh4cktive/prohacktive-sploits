import os
import sys
import colors

from multiprocessing import Process, Value
import time


class CProcess(Process):
    def __init__(self, name, function, *args):
        Process.__init__(self, name=name)
        # Shared value between processes
        self.terminated = Value('b', False)
        self.function = function
        self.args = list(args)

    def run(self):
        ret = self.function(*self.args)
        self.terminated.value = True
        return ret


def handle_processes(processes_list, processes_running_limit, sleep_time=None):
    processes_running = list()
    while True:
        processes_len = len(processes_running)
        # Start x processes by x processes by default
        if processes_len < processes_running_limit and len(processes_list) != 0:
            # Get the first into the list
            process = processes_list[0]
            process.start()
            colors.print_warn("[-] Process running %s" % process.name)
            # Remove from processes list
            processes_list.remove(process)
            processes_running.append(process)
        else:
            # Wait for atleast one process terminating
            for process in processes_running:
                if process.terminated.value:
                    # Shouldn't take long to close itself
                    process.join()
                    processes_running.remove(process)
            # Sleep for cpu usage
            if sleep_time:
                time.sleep(sleep_time)
            # No more processes to run
            if len(processes_running) == 0:
                break
