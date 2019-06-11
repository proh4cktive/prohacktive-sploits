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

magic_dict = {"\x1f\x8b\x08": "gz",
              "\x42\x5a\x68": "bz2", "\x50\x4b\x03\x04": "zip"}
max_dict_len = max(len(x) for x in magic_dict)


def get_fetched_srcs_dir():
    return temp_dir + "fetched_srcs/"


if not os.path.exists(get_fetched_srcs_dir()):
    os.mkdir(get_fetched_srcs_dir())


def is_compressed(data):
    for magic, filetype in magic_dict.items():
        if data == magic:
            return filetype
    return None


def is_file_compressed(filename):
    with open(filename, "rb") as f:
        file_start = f.read(max_dict_len)
        f.close()
        return is_compressed(file_start.data)
    return None


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
        return None


def read_file(filename):
    if os.path.isfile(filename):
        file = open(filename, "r")
        data = file.read()
        file.close()
        return data
    else:
        return None


def read_file_bytes(filename) -> bytes:
    if os.path.isfile(filename):
        file = open(filename, "rb")
        data = file.read()
        file.close()
        return bytes(data)
    else:
        return None


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
    def fetch(self):
        try:
            response = requests.get(self.url)
        except requests.RequestException as e:
            colors.print_error("[!]" + e)
            return None

        # Get response
        data = response.content

        # Check if data is compressed
        if is_compressed(data):
            temp_filename = "tempfile"
            # Write to temporary file the response
            if not os.path.exists(temp_dir):
                os.mkdir(temp_dir)

            # Sadly we need to write it to a file because pyunpack can't yet
            # decompress from binary data directly from memory
            temp_file = open(temp_dir + temp_filename, "wb")
            temp_file.write(data)
            temp_file.close()

            # Decompress
            arch = pyunpack.Archive(temp_dir + temp_filename)
            arch.extractall(temp_dir)
            # Read decompressed file and output it
            # There should be only one file anyway
            filename = os.listdir(temp_dir)[0]
            temp_file = open(temp_dir + filename, "rb")
            data = temp_file.read()
            temp_file.close()
            # Don't forget to remove it
            os.remove(temp_dir + filename)
            # This one also
            os.remove(temp_dir + temp_filename)
        return data
