import os
import sys
import json

runPath = os.path.dirname(os.path.realpath(__file__+"../../"))
sys.path.append(runPath + "/lib/")

import colors
import ph_db
from src_helper import SrcHelper

class CISecurityDB():
    def __init__(self):
        src = SrcHelper(
            "https://oval.cisecurity.org/repository/download/5.11.1/all/oval.xml.zip")
        self.data = src.fetch()

def fetch_handler():
    cisecurity = CISecurityDB()
    return cisecurity.data
