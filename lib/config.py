import os
import sys
import colors
import configparser

runPath = os.path.dirname(os.path.realpath(__file__ + "../../"))

config_filename = "/etc/prohacktive.conf"


class Config():
    def __init__(self, db_host="localhost", db_port=27017,
                 db_name="prohacktive", db_user="", db_password="",
                 vulners_api_key="", thread_limit_update=8, thread_limit_fetch=8):
        self.db_host = db_host
        self.db_port = int(db_port)
        self.db_name = db_name
        self.db_user = db_user
        self.db_password = db_password
        self.vulners_api_key = vulners_api_key
        self.thread_limit_fetch = int(thread_limit_fetch)
        self.thread_limit_update = int(thread_limit_update)

    def get(self):
        config_gen = configparser.ConfigParser()
        config_gen["DATABASE"] = {
            "db_host": self.db_host,
            "db_port": str(self.db_port),
            "db_name": self.db_name,
            "db_user": self.db_user,
            "db_pass": self.db_password}
        config_gen["VULNERS"] = {"vulners_api_key": self.vulners_api_key}
        config_gen["THREADS"] = {
            "thread_limit_update": int(self.thread_limit_update), "thread_limit_fetch": int(self.thread_limit_fetch)}
        return config_gen


default_config = Config()
current_config = default_config

colors.print_info("[-] Parsing %s" % config_filename)
config = configparser.ConfigParser()
dataset = config.read(config_filename)
if len(dataset) == 0:
    colors.print_error("[!] Couldn't read config file at %s" % config_filename)
    colors.print_warn("[!] Using default configuration")
else:
    db = config["DATABASE"]
    vulners_api_key = config["VULNERS"]["vulners_api_key"]
    threads = config["THREADS"]
    current_config = Config(
        db["db_host"],
        db["db_port"],
        db["db_name"],
        db["db_user"],
        db["db_pass"],
        vulners_api_key,
        threads["thread_limit_update"],
        threads["thread_limit_fetch"])
