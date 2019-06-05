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


def getFetchedSrcsDir():
    return temp_dir + "fetched_srcs/"


if not os.path.exists(getFetchedSrcsDir()):
    os.mkdir(getFetchedSrcsDir())


def isCompressed(data):
    for magic, filetype in magic_dict.items():
        if data == magic:
            return filetype
    return None


def isFileCompressed(filename):
    with open(filename, "rb") as f:
        file_start = f.read(max_dict_len)
        f.close()
        return isCompressed(file_start.data)
    return None


def makeSig(data):
    if not isinstance(data, bytearray):
        raise "Expected the data to be a bytearray"
    h = hashlib.sha256(data).hexdigest()
    return bytearray(h.encode("ascii"))


def makeSigFromFile(filename):
    if os.path.isfile(filename):
        file = open(filename, "rb")
        hashed_file = makeSig(file.read())
        file.close()
        return hashed_file
    else:
        return None


def readFile(filename):
    if os.path.isfile(filename):
        file = open(filename, "r")
        data = file.read()
        file.close()
        return data
    else:
        return None


def readFileBytes(filename):
    if os.path.isfile(filename):
        file = open(filename, "rb")
        data = file.read()
        file.close()
        return bytearray(data)
    else:
        return None


def writeFileBytes(filename, data):
    if not isinstance(data, bytearray):
        raise "Expected the data to be a bytearray"
    file = open(filename, "wb")
    file.write(data)
    file.close()
    return data


def writeFile(filename, data):
    file = open(filename, "w")
    file.write(data)
    file.close()
    return data


def readSource(sourcename):
    sourcename = getFetchedSrcsDir() + sourcename
    return readFileBytes(sourcename)


def writeSource(sourcename, data):
    sourcename = getFetchedSrcsDir() + sourcename
    writeFileBytes(sourcename, data)


def readSourceSig(sourcename):
    sourcename = getFetchedSrcsDir() + sourcename + ".sig"
    return readFileBytes(sourcename)


def writeSourceSig(sourcename, data):
    sourcename = getFetchedSrcsDir() + sourcename + ".sig"
    writeFileBytes(sourcename, data)


class SrcHelper():
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
        if isCompressed(data):
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
