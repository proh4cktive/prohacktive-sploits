import os
import pymongo
import json
import colors
import config
from datetime import datetime

runPath = os.path.dirname(os.path.realpath(__file__ + "../../"))


class Statistics():
    def __init__(self, src_name):
        self.exploit_updates = list()
        self.exploit_inserts = list()
        self.src_name = src_name
        # Timestamp at init
        self.timestamp = datetime.now().timestamp()

    def exploit_update(self, exploit_id):
        self.exploit_updates.append(exploit_id)

    def exploit_insert(self, exploit_id):
        self.exploit_inserts.append(exploit_id)

    def gen_dict(self):
        dictionary = {
            "source": self.src_name,
            "timestamp": self.timestamp,
            "inserts": self.exploit_inserts,
            "updates": self.exploit_updates}
        return dictionary


class ProHacktiveDB():
    def __init__(self, host=config.current_config.db_host,
                 port=config.current_config.db_port,
                 db_name=config.current_config.db_name,
                 user=config.current_config.db_user,
                 password=config.current_config.db_user):
        self.port = port
        self.host = host
        self.db_name = db_name
        self.user = user
        self.password = password
        self.stats = list()

        try:
            self.db = pymongo.MongoClient(
                host, port, username=user, password=password, maxPoolSize=None)
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)

        self.collections = self.db[self.db_name]

    def get_collection(self, name):
        collection = self.collections.get_collection(name)
        return collection

    def list_collections(self):
        return self.collections.list_collections()

    # Search exploit by id
    def search_exploit_id(self, unique_id):
        result = dict()
        for collection_name in self.collections.list_collection_names():
            if collection_name in self.collection_blacklist():
                continue
            collection = self.get_collection(collection_name)
            result[collection.name()] = collection.find({"_id": unique_id})
        return result

    # Return a tuple of Unique IDs or CVE IDs with source name
    def search_text_all_exploits(self, searched_text):
        exploits_id = list()
        for collection_name in self.collections.list_collection_names():
            if collection_name in self.collection_blacklist():
                continue
            collection = self.get_collection(collection_name)
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

    def insert_exploit(self, exploit, collection_name):
        collection = self.get_collection(collection_name)
        # TODO: See what kind of fields have been updated
        try:
            collection.insert_one(exploit)
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)
            stats = self.find_local_stats(collection_name)
            stats.exploit_inserts.append(exploit["_id"])

    def update_exploit(self, exploit, collection_name):
        collection = self.get_collection(collection_name)
        # Try to update first
        try:
            result = collection.update_one(
                {"_id": exploit["_id"]},
                {"$set": exploit})
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)

            # If it doesn't exist, insert it
            if result.matched_count == 0:
                self.insert_exploit(exploit, collection_name)
            else:
                stats = self.find_local_stats(collection_name)
                stats.exploit_updates.append(exploit["_id"])

    # Signatures methods
    def insert_src_sig(self, src_name, sig):
        collection = self.get_collection(self.get_srcs_sigs_collection_name())
        try:
            collection.insert_one({"_id": src_name, "sig": sig})
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)

    def update_src_sig(self, src_name, sig):
        collection = self.get_collection(self.get_srcs_sigs_collection_name())
        # Try to update first
        try:
            result = collection.update_one(
                {"_id": src_name}, {"$set": {"sig": sig}})
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)
            # If it doesn't exist, insert it
            if result.matched_count == 0:
                self.insert_src_sig(src_name, sig)

    def get_srcs_sigs(self):
        return list(self.get_collection(self.get_srcs_sigs_collection_name()).find())

    def update_srcs_sigs(self, src_sigs):
        for src_sig in src_sigs:
            self.update_src_sig(src_sig["_id"], src_sig["sig"])

    def find_src_name_from_sig(self, sig):
        src_sigs = self.get_srcs_sigs()
        for src_sig in src_sigs:
            if src_sig["sig"] == sig:
                return src_sig["_id"]
        return None

    def find_src_sig_from_name(self, name):
        src_sigs = self.get_srcs_sigs()
        for src_sig in src_sigs:
            if src_sig["_id"] == name:
                return src_sig["sig"]
        return None

    # Stats
    def drop_remote_stats(self):
        self.collections.drop_collection(self.get_stats_collection_name())

    def find_index_local_stats(self, name, create_not_found=True):
        for index in range(len(self.stats)):
            stats = self.stats[index]
            if stats.src_name == name:
                return index

        if create_not_found:
            self.stats.append(Statistics(name))
            return index
        else:
            raise "Couldn't find stats %s" % name

    def find_local_stats(self, name, create_not_found=True):
        return self.stats[self.find_index_local_stats(name, create_not_found)]

    def update_remote_stats(self):
        collection_stats = self.get_collection(self.get_stats_collection_name())
        for stats in self.stats:
            stats_dict = stats.genDict()
            collection_stats.insert_one(stats_dict)

    # Others collections name methods etc..
    def get_srcs_sigs_collection_name(self):
        return "src_signatures"

    def get_stats_collection_name(self):
        return "statistics"

    def collection_blacklist(self):
        return [self.get_srcs_sigs_collection_name(), self.get_stats_collection_name()]

    def __del__(self):
        # Inserts stats at the end of connection
        colors.print_info(
            "[-] Updating stats on %s:%i" %
            (self.host, self.port))
        self.update_remote_stats()
