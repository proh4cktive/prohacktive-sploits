import os
import sys
import pymongo
import json
import colors
import config
from datetime import datetime

runPath = os.path.dirname(os.path.realpath(__file__ + "../../"))


"""
{
    "_id": "<class 'str'>",
    "_index": "<class 'str'>",
    "_score": "<class 'NoneType'>",
    "_source": {
        "affectedSoftware": [
            {
                "name": "<class 'str'>",
                "operator": "<class 'str'>",
                "version": "<class 'str'>"
            }
        ],
        "assessment": {
            "href": "<class 'str'>",
            "name": "<class 'str'>",
            "system": "<class 'str'>"
        },
        "bulletinFamily": "<class 'str'>",
        "cpe": [
            "<class 'str'>"
        ],
        "cpe23": [
            "<class 'str'>"
        ],
        "cvelist": [
            "<class 'str'>"
        ],
        "cvss": {
            "score": [
                "WARNING!!! It is represented as a list but it is for showing the multiples data type here!",
                "<class 'float'>",
                "<class 'int'>"
            ],
            "vector": "<class 'str'>"
        },
        "cvss2": {
            "acInsufInfo": "<class 'bool'>",
            "cvssV2": {
                "accessComplexity": "<class 'str'>",
                "accessVector": "<class 'str'>",
                "authentication": "<class 'str'>",
                "availabilityImpact": "<class 'str'>",
                "baseScore": "<class 'float'>",
                "confidentialityImpact": "<class 'str'>",
                "integrityImpact": "<class 'str'>",
                "vectorString": "<class 'str'>",
                "version": "<class 'str'>"
            },
            "exploitabilityScore": "<class 'float'>",
            "impactScore": "<class 'float'>",
            "obtainAllPrivilege": "<class 'bool'>",
            "obtainOtherPrivilege": "<class 'bool'>",
            "obtainUserPrivilege": "<class 'bool'>",
            "severity": "<class 'str'>",
            "userInteractionRequired": "<class 'bool'>"
        },
        "cvss3": {
            "cvssV3": {
                "attackComplexity": "<class 'str'>",
                "attackVector": "<class 'str'>",
                "availabilityImpact": "<class 'str'>",
                "baseScore": "<class 'float'>",
                "baseSeverity": "<class 'str'>",
                "confidentialityImpact": "<class 'str'>",
                "integrityImpact": "<class 'str'>",
                "privilegesRequired": "<class 'str'>",
                "scope": "<class 'str'>",
                "userInteraction": "<class 'str'>",
                "vectorString": "<class 'str'>",
                "version": "<class 'str'>"
            },
            "exploitabilityScore": "<class 'float'>",
            "impactScore": "<class 'float'>"
        },
        "cwe": [
            "<class 'str'>"
        ],
        "description": "<class 'str'>",
        "edition": "<class 'int'>",
        "enchantments": {
            "dependencies": {
                "modified": "<class 'str'>",
                "references": [
                    {
                        "idList": [
                            "<class 'str'>"
                        ],
                        "type": "<class 'str'>"
                    }
                ]
            },
            "score": {
                "modified": "<class 'str'>",
                "value": "<class 'float'>",
                "vector": "<class 'str'>"
            }
        },
        "href": "<class 'str'>",
        "id": "<class 'str'>",
        "lastseen": "<class 'str'>",
        "modified": "<class 'str'>",
        "published": "<class 'str'>",
        "references": [
            "<class 'str'>"
        ],
        "reporter": "<class 'str'>",
        "scheme": "<class 'NoneType'>",
        "title": "<class 'str'>",
        "type": "<class 'str'>",
        "viewCount": "<class 'int'>"
    },
    "_type": "<class 'str'>",
    "sort": [
        "<class 'int'>"
    ]
}
"""


class Statistics():
    def __init__(self, collection_name):
        self.exploit_updates = list()
        self.exploit_inserts = list()
        self.collection_name = collection_name
        # Timestamp at init
        self.timestamp = datetime.now().timestamp()

    def exploitUpdate(self, exploit_id):
        self.exploit_updates.append(exploit_id)

    def exploitInsert(self, exploit_id):
        self.exploit_inserts.append(exploit_id)


class ProHacktiveDB():
    def __init__(self, host=config.current_config.db_host, port=config.current_config.db_port, db_name=config.current_config.db_name, user=config.current_config.db_user, password=config.current_config.db_user):
        self.port = port
        self.host = host
        self.db_name = db_name
        self.user = user
        self.password = password
        self.stats = list()

        try:
            self.db = pymongo.MongoClient(
                host, port, username=user, password=password)
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)

        self.collections = self.db[self.db_name]
        for collection_name in self.collections.list_collection_names():
            # Ignore srcs signature
            if collection_name in self.collectionsBlacklist():
                continue
            self.stats.append(Statistics(collection_name))

    # Stats methods
    def initLocalStats(self, collections_name):
        self.stats = list()
        for collection_name in collections_name:
            self.stats.append(Statistics(collection_name))

    def eraseRemoteStats(self):
        self.collections.drop_collection(self.getStatsCollectionName())

    def findLocalStatsIdByName(self, name):
        for i in range(len(self.stats)):
            if self.stats[i].collection_name == name:
                return i
        raise "Couldn't find stats %s" % name

    def getLocalStats(self, name):
        return self.stats[self.findLocalStatsIdByName(name)]

    def insertStats(self):
        for stats in self.stats:
            dict_stats = {"source": stats.collection_name, "timestamp": stats.timestamp,
                          "inserted": stats.exploit_inserts, "updated": stats.exploit_updates}
            collection = self.getCollection(self.getStatsCollectionName())
            try:
                collection.insert_one(dict_stats)
            except pymongo.errors.PyMongoError as e:
                colors.print_error(e)

    def getCollection(self, name):
        collection = self.collections.get_collection(name)
        return collection

    def listCollections(self):
        return self.collections.list_collections()

    # Search exploit by id
    def searchExploitById(self, unique_id):
        result = dict()
        for collection_name in self.collections.list_collection_names():
            # Ignore getSrcSigsCollectionName()
            if collection_name in self.collectionsBlacklist():
                continue
            collection = self.getCollection(collection_name)
            result[collection.name()] = collection.find({"_id": unique_id})
        return result

    # Return a tuple of Unique IDs or CVE IDs with source name
    def searchTextInAllExploits(self, searched_text):
        exploits_id = list()
        for collection_name in self.collections.list_collection_names():
            # Ignore getSrcSigsCollectionName()
            if collection_name in self.collectionsBlacklist():
                continue
            collection = self.getCollection(collection_name)
            # Get all data to find
            text_exploits = collection.find()
            # Load json
            exploits = json.loads(text_exploits)
            # For each exploit find the text
            for exploit in exploits:
                # Convert to string
                text_exploit = str(exploit)
                # We found in the exploit the text
                if searched_text in text_exploit:
                    exploits_id.append((exploit["_id"], collection_name))
        return exploits_id

    def insertExploit(self, exploit, collection_name):
        collection = self.getCollection(collection_name)
        # TODO: See what kind of fields have been updated
        try:
            collection.insert_one(exploit)
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)
        self.getLocalStats(collection_name).exploitInsert(exploit["_id"])

    def updateExploit(self, exploit, collection_name):
        collection = self.getCollection(collection_name)
        # Try to update first
        try:
            result = collection.update_one(
                {"_id": exploit["_id"]},
                {"$set": exploit})
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)

            # If it doesn't exist, insert it
            if result.matched_count == 0:
                self.insertExploit(exploit, collection_name)
            # Else we add it to the counter statistics
            else:
                self.getLocalStats(
                    collection_name).exploitUpdate(exploit["_id"])

    # Signatures methods
    def insertSrcSignature(self, src_name, sig):
        collection = self.getCollection(self.getSrcSigsCollectionName())
        try:
            collection.insert_one({"_id": src_name, "sig": sig})
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)

    def updateSrcSignature(self, src_name, sig):
        collection = self.getCollection(self.getSrcSigsCollectionName())
        # Try to update first
        try:
            result = collection.update_one(
                {"_id": src_name}, {"$set": {"sig": sig}})
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)
            # If it doesn't exist, insert it
            if result.matched_count == 0:
                self.insertSrcSignature(src_name, sig)

    def getSrcSignatures(self):
        return list(self.getCollection(self.getSrcSigsCollectionName()).find())

    def updateSrcsSignatures(self, src_sigs):
        for src_sig in src_sigs:
            self.updateSrcSignature(src_sig["_id"], src_sig["sig"])

    def findSrcNameFromSig(self, sig):
        src_sigs = self.getSrcSignatures()
        for src_sig in src_sigs:
            if src_sig["sig"] == sig:
                return src_sig["_id"]
        return None

    def findSrcSigFromName(self, name):
        src_sigs = self.getSrcSignatures()
        for src_sig in src_sigs:
            if src_sig["_id"] == name:
                return src_sig["sig"]
        return None

    # Others collections name methods etc..
    def getSrcSigsCollectionName(self):
        return "src_signatures"

    def getStatsCollectionName(self):
        return "statistics"

    def collectionsBlacklist(self):
        return [self.getSrcSigsCollectionName(), self.getStatsCollectionName()]


# Init DB
phdb = ProHacktiveDB()
