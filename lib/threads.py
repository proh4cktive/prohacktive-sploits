import os
import sys
import colors

from threading import Thread
from threading import Event
import time


class CThread(Thread):
    def __init__(self, name, function, *args):
        Thread.__init__(self, name=name)
        self.terminated = False
        self.function = function
        self.args = list(args)

    def run(self):
        # Unpack args and run function
        ret = self.function(*self.args)
        self.terminated = True
        return ret


def handleThreads(threads_list, threads_running_limit, sleep_time=None):
    threads_running = list()
    while True:
        threads_len = len(threads_running)
        # Start x threads by x threads by default
        if threads_len < threads_running_limit:
            # Get first thread into the list
            thread = threads_list[0]
            thread.start()
            colors.print_warn("[-] Thread running %s" % thread.name)
            # Remove from threads list
            threads_list.remove(thread)
            threads_running.append(thread)
        else:
            # Wait for atleast one thread terminating
            for thread in threads_running:
                if thread.terminated:
                    # Shouldn't take long to close itself
                    thread.join()
                    threads_running.remove(thread)
            # Sleep for cpu usage
            if sleep_time:
                time.sleep(sleep_time)
            # No more threads to run
            if len(threads_running) == 0:
                break
