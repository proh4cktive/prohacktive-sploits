import os
import sys
import json
import requests
import pyunpack
import colors
import hashlib

# Credits for saving my time:
# https://stackoverflow.com/questions/13044562/python-mechanism-to-identify-compressed-file-type-and-uncompress
srcs_dir = "srcs/"
runPath = os.path.dirname(os.path.realpath(__file__ + "../../"))
sys.path.append(runPath + "/" + srcs_dir)
temp_dir = runPath + "/tmp/"

if not os.path.exists(temp_dir):
    os.mkdir(temp_dir)

# File magic number / signatures
magic_dict = {(0x1f, 0x8b, 0x08, "gz"),
              (0x42, 0x5a, 0x68, "bz2"), (0x50, 0x4b, 0x03, 0x04, "zip")}
max_dict_len = max(len(x) for x in magic_dict)


def get_fetched_srcs_dir():
    return temp_dir + "fetched_srcs/"


if not os.path.exists(get_fetched_srcs_dir()):
    os.mkdir(get_fetched_srcs_dir())


def is_compressed(data):
    for magic in magic_dict:
        if magic[0] in data:
            return magic[1]
    return False


def is_file_compressed(filename):
    with open(filename, "rb") as f:
        file_start = f.read(max_dict_len)
        f.close()
        return is_compressed(file_start)
    return False


def make_sig(data) -> bytes:
    if not isinstance(data, bytes):
        raise Exception("Expected the data to be a bytes")
    h = hashlib.sha256(data).hexdigest()
    return bytes(h.encode("utf8"))


def make_sig_from_file(filename):
    if os.path.isfile(filename):
        file = open(filename, "rb")
        hashed_file = make_sig(file.read())
        file.close()
        return hashed_file
    else:
        return False


def read_file(filename):
    if os.path.isfile(filename):
        file = open(filename, "r")
        data = file.read()
        file.close()
        return data
    else:
        return False


def read_file_bytes(filename) -> bytes:
    if os.path.isfile(filename):
        file = open(filename, "rb")
        data = file.read()
        file.close()
        return bytes(data)
    else:
        return False


def write_file_bytes(filename, data):
    if not isinstance(data, bytes):
        raise Exception("Expected the data to be a bytes")
    file = open(filename, "wb")
    file.write(data)
    file.close()
    return data


def write_file(filename, data):
    file = open(filename, "w")
    file.write(data)
    file.close()
    return data


def read_source(sourcename) -> bytes:
    sourcename = get_fetched_srcs_dir() + sourcename
    return read_file_bytes(sourcename)


def write_source(sourcename, data):
    sourcename = get_fetched_srcs_dir() + sourcename
    write_file_bytes(sourcename, data)


def read_source_sig(sourcename) -> bytes:
    sourcename = get_fetched_srcs_dir() + sourcename + ".sig"
    return read_file_bytes(sourcename)


def write_source_sig(sourcename, data):
    sourcename = get_fetched_srcs_dir() + sourcename + ".sig"
    write_file_bytes(sourcename, data)


class SourceHelper():
    def __init__(self, url):
        self.url = url

    # Fetch database
    def fetch(self) -> bytes:
        try:
            response = requests.get(self.url)
        except requests.RequestException as e:
            colors.print_error("[!]" + e)
            return False

        # Get response
        data = response.content

        # Check if data is compressed
        if is_compressed(data):
            colors.print_info("[-] Decompressing %s" % self.url)
            # Write to temporary file the response
            if not os.path.exists(temp_dir):
                os.mkdir(temp_dir)
            
            temp_filename = temp_dir + "tempfile"
            # Sadly we need to write it to a file because pyunpack can't yet
            # decompress from binary data directly from memory
            temp_file = open(temp_filename, "wb")
            temp_file.write(data)
            temp_file.close()

            # Decompress
            filename = temp_filename
            archive_dir = temp_dir + "archive/"
            
            if not os.path.exists(archive_dir):
                os.mkdir(archive_dir)
                        
            # Sometimes it's compressed multiple times
            while(True):
                arch = pyunpack.Archive(filename)
                arch.extractall(archive_dir)
                os.remove(filename)
                filename = archive_dir + os.listdir(archive_dir)[0]
                compressed = is_file_compressed(filename)
                if not compressed:
                    break

        temp_file = open(filename, "rb")
        data = bytes(temp_file.read())
        temp_file.close()
        os.remove(filename)
        return data
