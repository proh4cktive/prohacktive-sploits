# ProHacktive-SPloits

ProHacktive-SPloits is a Python exploit database fetcher and searcher powered with MongoDB and inspired by cve-search and VIA4CVE (Currently in development)

## Installation

Requirements:

- Basic knowneldge of linux usage

- python-pip or python3-pip package, depending on wich version of python you want to use
```bash
sudo apt-get update && sudo apt-get install python3-pip
```
- Install the python libraries inside requirements:

```bash
sudo pip install -U -r requirements
```

## Usage

- First you need configuration file in /etc/prohacktive.conf, Example in the source folder (etc/prohacktive.conf):
```bash
sudo vim /etc/prohacktive.conf

# ----- prohacktive.conf ----- #

[DATABASE]
db_host = localhost
db_port = 27017
db_name = prohacktive
db_user = <your username leave empty otherwhise>
db_pass = <your pass leave empty otherwhise>

[VULNERS]
# Vulners.com API Key
vulners_api_key = XXXXXXXXXXXXXXXXXXXXXX

[PROCESSES]
# Limit processes for source updating
process_limit_update = 8
# Limit processes for source fetching
process_limit_fetch = 8
```

- Fetching all the sources:
```bash
python3 prohacktive_fetch.py
```
This will download all the database from different +100 sources into a folder called ```tmp/fetched_srcs/``` inside the repository that you have cloned.

It can take up to 15 minutes (depending on your connection) to download all the sources the first time
If you're running this command multiples times a day though, it can take only 1-2 minutes

- To init all the sources to the MongoDB database:
```bash
python3 prohacktive_init_db.py
```
This will read all the sources fetched inside ```tmp/fetched_srcs/``` directory, and insert all exploits & erase old exploits inside the database.
It can take up to 30-60 seconds on MongoDB with a localhost, but could take more time with a remote host

This will also for each sources creates a collection inside your database

- To update all the sources to the MongoDB database:
```bash
python3 prohacktive_update_db.py
```
- After you have updated the source files, you can run this command to update the MongoDB database fastly. If you do it often, it can take 1-3 seconds if not less

- For helping the analyzing/parsing of a JSON file for the sources that have been fetched you can use this python script this way in a terminal:

```bash
python3 json_analyzer.py <path to file>
...
python3 json_analyzer.py tmp/fetched_srcs/Vulners_cve
```

## Adding more sources

You can add more sources to the ```srcs/``` folder by writing a python module.

In order to get proper data, you'll need to write python module by downloading from the source (can be different format) and convert it into a JSON file / list of dictionaries (you can take the model from Vulners) so the source manager can insert it into the MongoDB database in a new collection for you.

The function that the source manager that will call by importing your python module is called ```fetch_handler()``` and the future sources needs to be written into ```tmp/fetched_src/``` so the source manager can read all the fetched sources without taking too much RAM.
