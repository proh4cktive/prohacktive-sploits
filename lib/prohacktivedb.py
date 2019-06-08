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

    def get_sources_collections_name(self):
        collections_name = list()
        for collection_name in self.collections.list_collection_names():
            if collection_name in self.collection_blacklist():
                continue
            collections_name.append(collection_name)
        return collections_name

    # Search exploit by id, return list of exploits (list should never be greater than 1)
    def search_exploit(self, unique_id, collection_name=None):
        result = list()
        # If no collection name was precised we append
        # For each sources the exploit found
        if not collection_name:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                result.append(
                    (self.search_exploit(
                        unique_id,
                        collection_name),
                        collection_name))
        else:
            # Otherwhise we just find the exploit in the source
            collection = self.get_collection(collection_name)
            result = collection.find({"_id": unique_id})
        return result

    # Can return a list of exploits ID or a tuple of list of exploits ID
    # and source name
    def search_text_in_exploits(self, searched_text, collection_name=None):
        exploits_id = list()
        # If the source is precised we append all the exploits ID
        # That corresponds to our
        if collection_name:
            collection = self.get_collection(collection_name)
            # Get all data to find into the text
            text_exploits = collection.find()
            # Load json text
            exploits = json.loads(text_exploits)
            # For each exploit find the text
            for exploit in exploits:
                # Convert to string
                text_exploit = str(exploit)
                # We found in the exploit the text
                if searched_text in text_exploit:
                    exploits_id.append(exploit["_id"])
        else:
            # Otherwhise recursively search text in exploits in every
            # sources
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits_id.append(
                    (self.search_text_in_exploits(
                        searched_text,
                        collection_name),
                        collection_name))

        return exploits_id

    # Can return a list of exploits ID or a tuple of list of exploits ID
    # and source name
    def search_exploit_software(
            self, software_name=None, version=None, operator=None,
            collection_name=None):

        exploits_id = list()
        # If collection name exists
        if collection_name:
            collection = self.get_collection(collection_name)
            find_query = dict()
            # Append different search if precised
            if version:
                find_query["_source.affectedSoftware.version"] = version
            if operator:
                find_query["_source.affectedSoftware.operator"] = operator
            if software_name:
                find_query["_source.affectedSoftware.name"] = software_name
            # Search wasn't precised
            if not find_query.keys():
                raise "search_exploit_software: not enough arguments"
            found_exploits = collection.find(find_query, {"_id": 1})
            for found_exploit in found_exploits:
                exploits_id.append(found_exploit["_id"])
        else:
            # Otherwhise recursively search software in every sources
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits_id.append(
                    (self.search_exploit_software(
                        software_name,
                        version,
                        operator,
                        collection_name),
                        collection_name))

        return exploits_id

    # Get all references from an exploit ID
    def search_exploit_id_references_id(self, exploit_id):
        references = list()
        collections_name = self.get_sources_collections_name()
        for collection_name in collections_name:
            collection = self.get_collection(collection_name)
            # For each collections find the exploit ID
            exploits = collection.find({"_id": exploit_id}, {
                                       "_id": 0, "_source.enchantments.dependencies.references.idList": 1})
            # Append references
            for exploit in exploits:
                exploit_references = exploit["_source"]["enchantments"]["dependencies"]["references"]
                for exploit_reference in exploit_references:
                    exploits_refs_id = exploit_reference["idList"]
                    for exploit_ref_id in exploits_refs_id: 
                        references.append(exploit_ref_id)
        return references

    # Returns a tuple of exploits and source name
    def search_exploit_id_references(self, exploit_id):
        references_id = self.search_exploit_id_references_id(exploit_id)
        result = list()
        collections_name = self.get_sources_collections_name()
        for reference_id in references_id:
            for collection_name in collections_name:
                collection = self.get_collection(collection_name)
                result.append((collection.find({"_id":reference_id}), collection_name))
        return result

    # Returns for each exploits a tuple of exploits and sourcename
    def search_exploits_id_references(self, exploits_id):
        result = list()
        for exploit_id in exploits_id:
            result.append(self.search_exploit_id_references(exploit_id))
        return result

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
        return list(self.get_collection(
            self.get_srcs_sigs_collection_name()).find())

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
            stats_dict = stats.gen_dict()
            collection_stats.insert_one(stats_dict)

    # Others collections name methods etc..
    def get_srcs_sigs_collection_name(self):
        return "src_signatures"

    def get_stats_collection_name(self):
        return "statistics"

    def collection_blacklist(self):
        return [self.get_srcs_sigs_collection_name(
        ), self.get_stats_collection_name()]

    def __del__(self):
        # Inserts stats at the end of connection
        colors.print_info(
            "[-] Updating stats on %s:%i" %
            (self.host, self.port))
        self.update_remote_stats()
