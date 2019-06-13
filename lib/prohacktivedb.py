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

    # Search exploit by id, return list of exploits ID or tuple of exploits ID and source
    def search_exploit(self, unique_id, collection_name=None):
        result = list()
        # If no collection name was precised we append
        # For each sources the exploit found
        if not collection_name:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits = self.search_exploit(
                    unique_id,
                    collection_name)
                if len(exploits) != 0:
                    result.append((exploits, collection_name))
        else:
            # Otherwhise we just find the exploit in the source
            collection = self.get_collection(collection_name)
            exploits = collection.find({"_id": unique_id})
            for exploit in exploits:
                result.append(exploit)
        return result

    # Search exploit with custom query & projection
    def search_exploits_id_with_query(self, query, proj, collection_name=None):
        result = list()
        if not collection_name:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits = self.search_exploits_id_with_query(
                    query, proj,
                    collection_name)
                if len(exploits) != 0:
                    result.append((exploits, collection_name))
        else:
            collection = self.get_collection(collection_name)
            exploits = collection.find(query, proj)
            for exploit in exploits:
                result.append(exploit)
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
            # Collection name doesn't exist?
            if not text_exploits:
                return
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
                searched_exploits = self.search_text_in_exploits(
                    searched_text,
                    collection_name)
                # Do not append if it didn't find anything
                if len(searched_exploits) != 0:
                    exploits_id.append((searched_exploits, collection_name))

        return exploits_id

    # Can return a list of exploits ID or a tuple of list of exploits ID
    # and source name
    def search_exploits_id_by_software(
            self, software_name=None, version=None, operator=None,
            collection_name=None):

        exploits_id = list()
        # If collection name exists
        if collection_name:
            collection = self.get_collection(collection_name)
            find_query = dict()
            # Append different search if precised
            if version:
                find_query["_source.affectedSoftware.version"] = {
                    "$regex": version}
            if operator:
                find_query["_source.affectedSoftware.operator"] = {
                    "$regex": operator}
            if software_name:
                find_query["_source.affectedSoftware.name"] = {
                    "$regex": software_name}
            # Search wasn't precised
            if not find_query.keys():
                raise Exception("search_exploit_software: not enough arguments")
            found_exploits = collection.find(find_query, {"_id": 1})
            for found_exploit in found_exploits:
                exploits_id.append(found_exploit["_id"])
        else:
            # Otherwhise recursively search software in every sources
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                softwares_affected = self.search_exploits_id_by_software(
                    software_name,
                    version,
                    operator,
                    collection_name)
                # Do not append if we have 0 softwares affected
                if len(softwares_affected) != 0:
                    exploits_id.append((softwares_affected, collection_name))

        return exploits_id

    # Date format: year-month-dayThour-minute-second
    # Example: 2016-09-26T17:22:32
    # Returns a tuple of exploits ID and sourcename or list of exploits ID
    def search_exploits_id_by_published_date(self, min_date=None, max_date=None, collection_name=None):
        result = list()
        if not min_date and not max_date:
            raise Exception("min_date and max_date were not set!")

        find_query = dict()
        find_query_date = dict()

        if min_date:
            find_query_date["$gte"] = min_date

        if max_date:
            find_query_date["$lt"] = max_date

        # Insert query between dates
        find_query["_source.published"] = find_query_date

        if collection_name:
            collection = self.get_collection(collection_name)
            exploits_id = collection.find(find_query, {"_id": 1})
            for exploit_id in exploits_id:
                result.append(exploit_id["_id"])
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits = self.search_exploits_id_by_published_date(
                    min_date, max_date, collection_name)
                if len(exploits) != 0:
                    result.append((exploits, collection_name))

        return result

    # Date format: year-month-dayThour-minute-second
    # Example: 2016-09-26T17:22:32
    # Returns a tuple of exploits ID and sourcename or list of exploits ID
    def search_exploits_id_by_modified_date(self, min_date=None, max_date=None, collection_name=None):
        result = list()
        if not min_date and not max_date:
            raise Exception("min_date and max_date were not set!")

        find_query = dict()
        find_query_date = dict()

        if min_date:
            find_query_date["$gte"] = min_date

        if max_date:
            find_query_date["$lt"] = max_date

        # Insert query between dates
        find_query["_source.modified"] = find_query_date

        if collection_name:
            collection = self.get_collection(collection_name)
            exploits_id = collection.find(find_query, {"_id": 1})
            for exploit_id in exploits_id:
                result.append(exploit_id["_id"])
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits = self.search_exploits_id_by_modified_date(
                    min_date, max_date, collection_name)
                if len(exploits) != 0:
                    result.append((exploits, collection_name))

        return result

    # Search exploits ID by score between 0 & 10
    def search_exploits_id_by_score(self, min_score=None, max_score=None, collection_name=None):
        result = list()
        if not min_score and not max_score:
            raise Exception("min_score and max_score were not set!")

        find_query = dict()
        find_query_score = dict()

        if min_score:
            find_query_score["$gte"] = min_score

        if max_score:
            find_query_score["$lt"] = max_score

        # Insert query between dates
        find_query["_source.enchantments.score.value"] = find_query_score

        if collection_name:
            collection = self.get_collection(collection_name)
            exploits_id = collection.find(find_query, {"_id": 1})
            for exploit_id in exploits_id:
                result.append(exploit_id["_id"])
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits = self.search_exploits_id_by_score(
                    min_score, max_score, collection_name)
                if len(exploits) != 0:
                    result.append((exploits, collection_name))

        return result

    def search_exploits_id_by_lastseen_date(self, min_date=None, max_date=None, collection_name=None):
        result = list()
        if not min_date and not max_date:
            raise Exception("min_date and max_date were not set!")

        find_query = dict()
        find_query_date = dict()

        if min_date:
            find_query_date["$gte"] = min_date

        if max_date:
            find_query_date["$lt"] = max_date

        # Insert query between dates
        find_query["_source.lastseen"] = find_query_date

        if collection_name:
            collection = self.get_collection(collection_name)
            exploits_id = collection.find(find_query, {"_id": 1})
            for exploit_id in exploits_id:
                result.append(exploit_id["_id"])
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits = self.search_exploits_id_by_lastseen_date(
                    min_date, max_date, collection_name)
                if len(exploits) != 0:
                    result.append((exploits, collection_name))

        return result

    # Returns a tuple of exploits id and source name
    # cpe:/ <part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
    #     "cpe": [
    #     "cpe:/a:microsoft:windows_server_2012:r2",
    #     "cpe:/a:microsoft:windows_10:1607",
    #     "cpe:/o:microsoft:windows_server_2012:r2",
    #     "cpe:/a:microsoft:windows_10:1511",
    #     "cpe:/a:microsoft:edge:*",
    #     "cpe:/a:microsoft:windows_10:-",
    #     "cpe:/o:microsoft:windows_10:-",
    #     "cpe:/o:microsoft:windows_server_2012:-",
    #     "cpe:/o:microsoft:windows_10:1607",
    #     "cpe:/o:microsoft:windows_10:1511",
    #     "cpe:/a:microsoft:windows_server_2012:-",
    #     "cpe:/o:microsoft:windows_8.1:*",
    #     "cpe:/a:microsoft:windows_8.1:*"
    # ],
    # "cpe23": [
    #     "cpe:2.3:o:microsoft:windows_10:1511:*:*:*:*:*:*:*",
    #     "cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*",
    #     "cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*",
    #     "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
    #     "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
    #     "cpe:2.3:o:microsoft:windows_8.1:*:*:*:*:*:*:*:*",
    #     "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*"
    # ],
    def search_exploits_id_by_cpe(self, cpe, collection_name=None):
        result = list()
        if collection_name:
            collection = self.get_collection(collection_name)
            query_dict = dict()
            query_dict["_source.cpe"] = {"$regex": cpe}
            exploits = collection.find(query_dict, {"_id": 1})
            for exploit in exploits:
                result.append(exploit["_id"])
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits = self.search_exploits_id_by_cpe(
                    cpe, collection_name)
                if len(exploits) != 0:
                    result.append((exploits, collection_name))
        return result

    def search_exploits_id_by_cpe23(self, cpe, collection_name=None):
        result = list()
        if collection_name:
            collection = self.get_collection(collection_name)
            query_dict = dict()
            query_dict["_source.cpe23"] = {"$regex": cpe}
            exploits = collection.find(query_dict, {"_id": 1})
            for exploit in exploits:
                result.append(exploit["_id"])
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits = self.search_exploits_id_by_cpe23(
                    cpe, collection_name)
                if len(exploits) != 0:
                    result.append((exploits, collection_name))
        return result

    # Returns list of exploits id or tuple of exploits id with source name
    def get_cvelist_by_exploit_id(self, exploit_id, collection_name=None):
        result = list()
        if collection_name:
            collection = self.get_collection(collection_name)
            # Maybe using find_one could be better if we're sure that the id exists only once
            exploits = collection.find({"_id": exploit_id}, {
                                       "_id": 0, "_source.cvelist": 1})
            for exploit in exploits:
                result.extend(exploit["_source"]["cvelist"])
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits = self.get_cvelist_by_exploit_id(
                    exploit_id, collection_name)
                if len(exploits) != 0:
                    result.append((exploits, collection_name))
        return result

    def get_exploits_id_from_source(self, collection_name):
        result = list()
        collection = self.get_collection(collection_name)
        exploits = collection.find({}, {"_id": 1})
        for exploit in exploits:
            result.append(exploit["_id"])
        return result

    def get_description_from_exploit_id(self, exploit_id, collection_name=None):
        result = list()
        if collection_name:
            collection = self.get_collection(collection_name)
            exploits = collection.find({"_id": exploit_id},
                                       {"_id": 0, "_source.description": 1})
            for exploit in exploits:
                result.append(exploit["_source"]["description"])
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits = self.get_description_from_exploit_id(
                    exploit_id, collection_name)
                if len(exploits) != 0:
                    result.append((exploits, collection_name))
        return result

    def get_references_links_from_exploit_id(self, exploit_id, collection_name=None):
        result = list()
        if collection_name:
            collection = self.get_collection(collection_name)
            exploits = collection.find({"_id": exploit_id}, {
                                       "_id": 0, "_source.references": 1})
            for exploit in exploits:
                ref_links = exploit["_source"]["references"]
                # Sometimes it is a list of links
                result.extend(ref_links)
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                exploits = self.get_references_links_from_exploit_id(
                    exploit_id, collection_name)
                if len(exploits) != 0:
                    result.append((exploits, collection_name))
        return result

    # Get all references from an exploit ID
    def get_references_id_from_exploit_id(self, exploit_id):
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
                    references.extend(exploits_refs_id)
        return references

    # Returns a tuple of exploits and source name
    def get_references_from_exploit_id(self, exploit_id):
        references_id = self.get_references_id_from_exploit_id(exploit_id)
        result = list()
        collections_name = self.get_sources_collections_name()
        for reference_id in references_id:
            for collection_name in collections_name:
                result_references = self.search_exploit(
                    reference_id, collection_name)
                if len(result_references) != 0:
                    result.append((result_references, collection_name))
        return result

    # Returns for each exploits a tuple of exploits and sourcename
    def get_references_from_exploits_id(self, exploits_id):
        result = list()
        for exploit_id in exploits_id:
            result.append(self.get_references_from_exploit_id(exploit_id))
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

    def insert_exploits(self, exploits, collection_name):
        collection = self.get_collection(collection_name)
        # TODO: See what kind of fields have been updated
        try:
            collection.insert_many(exploits)
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)
        stats = self.find_local_stats(collection_name)
        for exploit in exploits:
            stats.exploit_inserts.append(exploit["_id"])

    # Update many exploits can't be really done because each exploits have very
    # Specific stuffs anyway

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
        collection = self.get_collection(self.get_srcs_sigs_collection_name())
        # find_one because it should be unique
        source_found = collection.find_one({"sig": sig})
        return source_found["_id"]

    def find_src_sig_from_name(self, name):
        collection = self.get_collection(self.get_srcs_sigs_collection_name())
        # find_one because it should be unique
        source_found = collection.find_one({"_id": name})
        return source_found["sig"]

    # Sources data & informations methods
    def insert_src_dat(self, src_name, dat):
        collection = self.get_collection(self.get_srcs_dat_collection_name())
        try:
            collection.insert_one({"_id": src_name, "dat": dat})
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)

    def update_src_dat(self, src_name, dat):
        collection = self.get_collection(self.get_srcs_dat_collection_name())
        # Try to update first
        try:
            result = collection.update_one(
                {"_id": src_name}, {"$set": {"dat": dat}})
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)
            # If it doesn't exist, insert it
            if result.matched_count == 0:
                self.insert_src_dat(src_name, dat)

    def get_srcs_dat(self):
        return list(self.get_collection(
            self.get_srcs_dat_collection_name()).find())

    def update_srcs_dat(self, src_dats):
        for src_dat in src_dats:
            self.update_src_dat(src_dat["_id"], src_dat["dat"])

    def find_src_name_from_dat(self, sig):
        collection = self.get_collection(self.get_srcs_dat_collection_name())
        # find_one because it should be unique
        source_found = collection.find_one({"dat": sig})
        return source_found["_id"]

    def find_src_dat_from_name(self, name):
        collection = self.get_collection(self.get_srcs_dat_collection_name())
        # find_one because it should be unique
        source_found = collection.find_one({"_id": name})
        return source_found["dat"]

    # Stats
    def drop_remote_stats(self):
        self.collections.drop_collection(self.get_stats_collection_name())

    def find_index_local_stats(self, name, create_not_found=True):
        index = -1
        for index in range(len(self.stats)):
            stats = self.stats[index]
            if stats.src_name == name:
                return index

        if create_not_found:
            self.stats.append(Statistics(name))
            return index
        else:
            raise Exception("Couldn't find stats %s" % name)

    def find_local_stats(self, name, create_not_found=True):
        return self.stats[self.find_index_local_stats(name, create_not_found)]

    def update_remote_stats(self):
        collection_stats = self.get_collection(self.get_stats_collection_name())
        for stats in self.stats:
            stats_dict = stats.gen_dict()
            collection_stats.insert_one(stats_dict)

    # Others collections name methods etc..
    def get_srcs_sigs_collection_name(self):
        return "sources_signatures"

    def get_srcs_dat_collection_name(self):
        return "sources_data"

    def get_stats_collection_name(self):
        return "sources_statistics"

    def collection_blacklist(self):
        return [self.get_srcs_sigs_collection_name(
        ), self.get_stats_collection_name(), self.get_srcs_dat_collection_name()]

    def __del__(self):
        # Inserts stats at the end of connection
        colors.print_info(
            "[-] Updating stats on %s:%i" %
            (self.host, self.port))

        self.update_remote_stats()
