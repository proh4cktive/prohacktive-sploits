import os
import pymongo
import json
import colors
import config
from datetime import datetime

runPath = os.path.dirname(os.path.realpath(__file__ + "../../"))


class Statistics():
    def __init__(self, src_name):
        self.vulnerability_updates = list()
        self.vulnerability_inserts = list()
        self.src_name = src_name
        # Timestamp at init
        self.timestamp = datetime.now().timestamp()

    def vulnerability_update(self, vulnerability_id):
        self.vulnerability_updates.append(vulnerability_id)

    def vulnerability_insert(self, vulnerability_id):
        self.vulnerability_inserts.append(vulnerability_id)

    def gen_dict(self):
        dictionary = {
            "source": self.src_name,
            "timestamp": self.timestamp,
            "inserts": self.vulnerability_inserts,
            "updates": self.vulnerability_updates}
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

    # Search vulnerability with custom query & projection
    def search_vulnerabilities_id_with_query(self, query, proj, collection_name=None):
        result = list()
        if not collection_name:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                vulnerabilities = self.search_vulnerabilities_id_with_query(
                    query, proj,
                    collection_name)
                if len(vulnerabilities) != 0:
                    result.append((vulnerabilities, collection_name))
        else:
            collection = self.get_collection(collection_name)
            vulnerabilities = collection.find(query, proj)
            for vulnerability in vulnerabilities:
                result.append(vulnerability)
        return result

    # Can return a list of vulnerabilities ID or a tuple of list of vulnerabilities ID
    # and source name
    def search_text_in_vulnerabilities(self, searched_text, collection_name=None):
        vulnerabilities_id = list()
        # If the source is precised we append all the vulnerabilities ID
        # That corresponds to our
        if collection_name:
            collection = self.get_collection(collection_name)
            # Get all data to find into the text
            text_vulnerabilities = collection.find()
            # Collection name doesn't exist?
            if not text_vulnerabilities:
                return
            # Load json text
            vulnerabilities = json.loads(text_vulnerabilities)
            # For each vulnerability find the text
            for vulnerability in vulnerabilities:
                # Convert to string
                text_vulnerability = str(vulnerability)
                # We found in the vulnerability the text
                if searched_text in text_vulnerability:
                    vulnerabilities_id.append(vulnerability["_id"])
        else:
            # Otherwhise recursively search text in vulnerabilities in every
            # sources
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                searched_vulnerabilities = self.search_text_in_vulnerabilities(
                    searched_text,
                    collection_name)
                # Do not append if it didn't find anything
                if len(searched_vulnerabilities) != 0:
                    vulnerabilities_id.append(
                        (searched_vulnerabilities, collection_name))

        return vulnerabilities_id

    def search_vulnerabilities_id(self, collection_name=None,
                                  vulnerability_id=None,
                                  min_published_date=None,
                                  max_published_date=None,
                                  min_modified_date=None,
                                  max_modified_date=None,
                                  min_score=None,
                                  max_score=None,
                                  min_lastseen_date=None,
                                  max_lastseen_date=None,
                                  software_name=None,
                                  version=None,
                                  operator=None,
                                  cpe=None,
                                  cpe23=None):
        result = list()
        find_query = dict()
        temp_dict = dict()

        if version:
            find_query["_source.affectedSoftware.version"] = {
                "$regex": version}
        if operator:
            find_query["_source.affectedSoftware.operator"] = {
                "$regex": operator}
        if software_name:
            find_query["_source.affectedSoftware.name"] = {
                "$regex": software_name}

        if min_published_date or max_published_date:
            if min_published_date:
                temp_dict["$gte"] = min_published_date
            if max_published_date:
                temp_dict["$lt"] = max_published_date
            find_query["_source.published"] = temp_dict

        if min_modified_date and max_modified_date:
            if min_modified_date:
                temp_dict["$gte"] = min_modified_date
            if max_modified_date:
                temp_dict["$lt"] = max_modified_date
            find_query["_source.modified"] = temp_dict

        if min_lastseen_date and max_lastseen_date:
            if min_lastseen_date:
                temp_dict["$gte"] = min_lastseen_date
            if max_lastseen_date:
                temp_dict["$lt"] = max_lastseen_date
            find_query["_source.lastseen"] = temp_dict

        if min_score and max_score:
            if min_score:
                temp_dict["$gte"] = min_score
            if max_score:
                temp_dict["$lt"] = max_score
            find_query["_source.enchantments.score.value"] = temp_dict

        if cpe:
            find_query["_source.cpe"] = {"$regex": cpe}

        if cpe23:
            find_query["_source.cpe23"] = {"$regex": cpe23}

        if vulnerability_id:
            find_query["_id"] = {"$regex": vulnerability_id}

        if collection_name:
            collection = self.get_collection(collection_name)
            vulnerabilities_id = collection.find(find_query, {"_id": 1})
            for vulnerability_id in vulnerabilities_id:
                result.append(vulnerability_id["_id"])
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                vulnerabilities = self.search_vulnerabilities_id(collection_name,
                                                                 min_published_date,
                                                                 max_published_date,
                                                                 software_name, version,
                                                                 operator, min_modified_date,
                                                                 max_modified_date, min_score,
                                                                 max_score, min_lastseen_date,
                                                                 max_lastseen_date, cpe)
                if len(vulnerabilities) != 0:
                    result.append((vulnerabilities, collection_name))

        return result

    # Search vulnerability by id,
    # return list of vulnerabilities or tuple of vulnerabilities and source
    def get_vulnerability_info(self, unique_id, collection_name=None):
        result = list()
        # If no collection name was precised we append
        # For each sources the vulnerability found
        if not collection_name:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                vulnerabilities = self.get_vulnerability_info(
                    unique_id,
                    collection_name)
                if len(vulnerabilities) != 0:
                    result.append((vulnerabilities, collection_name))
        else:
            # Otherwhise we just find the vulnerability in the source
            collection = self.get_collection(collection_name)
            vulnerabilities = collection.find({"_id": unique_id})
            for vulnerability in vulnerabilities:
                result.append(vulnerability)
        return result

    # Returns list of vulnerabilities id or tuple of vulnerabilities id with source name
    def get_cvelist_by_vulnerability_id(self, vulnerability_id, collection_name=None):
        result = list()
        if collection_name:
            collection = self.get_collection(collection_name)
            # Maybe using find_one could be better if we're sure that the id exists only once
            vulnerabilities = collection.find({"_id": vulnerability_id}, {
                "_id": 0, "_source.cvelist": 1})
            for vulnerability in vulnerabilities:
                result.extend(vulnerability["_source"]["cvelist"])
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                vulnerabilities = self.get_cvelist_by_vulnerability_id(
                    vulnerability_id, collection_name)
                if len(vulnerabilities) != 0:
                    result.append((vulnerabilities, collection_name))
        return result

    def get_vulnerabilities_id_from_source(self, collection_name):
        result = list()
        collection = self.get_collection(collection_name)
        vulnerabilities = collection.find({}, {"_id": 1})
        for vulnerability in vulnerabilities:
            result.append(vulnerability["_id"])
        return result

    def get_description_from_vulnerability_id(self, vulnerability_id, collection_name=None):
        result = list()
        if collection_name:
            collection = self.get_collection(collection_name)
            vulnerabilities = collection.find({"_id": vulnerability_id},
                                              {"_id": 0, "_source.description": 1})
            for vulnerability in vulnerabilities:
                result.append(vulnerability["_source"]["description"])
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                vulnerabilities = self.get_description_from_vulnerability_id(
                    vulnerability_id, collection_name)
                if len(vulnerabilities) != 0:
                    result.append((vulnerabilities, collection_name))
        return result

    def get_references_links_from_vulnerability_id(self, vulnerability_id, collection_name=None):
        result = list()
        if collection_name:
            collection = self.get_collection(collection_name)
            vulnerabilities = collection.find({"_id": vulnerability_id}, {
                "_id": 0, "_source.references": 1})
            for vulnerability in vulnerabilities:
                ref_links = vulnerability["_source"]["references"]
                # Sometimes it is a list of links
                result.extend(ref_links)
        else:
            collections_name = self.get_sources_collections_name()
            for collection_name in collections_name:
                vulnerabilities = self.get_references_links_from_vulnerability_id(
                    vulnerability_id, collection_name)
                if len(vulnerabilities) != 0:
                    result.append((vulnerabilities, collection_name))
        return result

    # Get all references from an vulnerability ID
    def get_references_id_from_vulnerability_id(self, vulnerability_id):
        references = list()
        collections_name = self.get_sources_collections_name()
        for collection_name in collections_name:
            collection = self.get_collection(collection_name)
            # For each collections find the vulnerability ID
            vulnerabilities = collection.find({"_id": vulnerability_id}, {
                "_id": 0, "_source.enchantments.dependencies.references.idList": 1})
            # Append references
            for vulnerability in vulnerabilities:
                vulnerability_references = vulnerability["_source"]["enchantments"]["dependencies"]["references"]
                for vulnerability_reference in vulnerability_references:
                    vulnerabilities_refs_id = vulnerability_reference["idList"]
                    references.extend(vulnerabilities_refs_id)
        return references

    # Returns for each vulnerabilities a tuple of vulnerabilities and sourcename
    def get_references_id_from_vulnerabilities_id(self, vulnerabilities_id):
        result = list()
        for vulnerability_id in vulnerabilities_id:
            result.append(
                self.get_references_id_from_vulnerability_id(vulnerability_id))
        return result

    def insert_vulnerability(self, vulnerability, collection_name):
        collection = self.get_collection(collection_name)
        # TODO: See what kind of fields have been updated
        try:
            collection.insert_one(vulnerability)
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)
        stats = self.find_local_stats(collection_name)
        stats.vulnerability_inserts.append(vulnerability["_id"])

    def update_vulnerability(self, vulnerability, collection_name):
        collection = self.get_collection(collection_name)
        # Try to update first
        try:
            result = collection.update_one(
                {"_id": vulnerability["_id"]},
                {"$set": vulnerability})
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)

        # If it doesn't exist, insert it
        if result.matched_count == 0:
            self.insert_vulnerability(vulnerability, collection_name)
        else:
            stats = self.find_local_stats(collection_name)
            stats.vulnerability_updates.append(vulnerability["_id"])

    def insert_vulnerabilities(self, vulnerabilities, collection_name):
        collection = self.get_collection(collection_name)
        # TODO: See what kind of fields have been updated
        try:
            collection.insert_many(vulnerabilities)
        except pymongo.errors.PyMongoError as e:
            colors.print_error(e)
        stats = self.find_local_stats(collection_name)
        for vulnerability in vulnerabilities:
            stats.vulnerability_inserts.append(vulnerability["_id"])

    # Update many vulnerabilities can't be really done because each vulnerabilities have very
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
