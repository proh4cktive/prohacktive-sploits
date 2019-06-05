from colorama import Fore, Back, Style
import time
from progressbar import AnimatedMarker, Bar, BouncingBar, Counter, ETA, \
    AdaptiveETA, FileTransferSpeed, FormatLabel, Percentage, \
    ProgressBar, ReverseBar, RotatingMarker, \
    SimpleProgress, Timer, UnknownLength


def print_error(message):
    print(Fore.RED + message)


def print_success(message):
    print(Fore.GREEN + message)


def print_warn(message):
    print(Fore.YELLOW + message)


def print_info(message):
    print(Fore.CYAN + message)


def print_progress_start(maxval=500):
    pbar = ProgressBar(widgets=[Percentage(), Bar()], maxval=maxval).start()
    pbar.start()
    return pbar
