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

# ----- prohacktive.conf -----

# Host of mongodb
[DATABASE]
db_host = localhost
db_port = 27017
db_name = prohacktive
db_user = <your username leave empty otherwhise>
db_pass = <your pass leave empty otherwhise>

[VULNERS]
# Vulners.com API Key
vulners_api_key = XXXXXXXXXXXXXXXXXXXXXX

[THREADS]
# Limit threads for source updating
thread_limit_update = 8
# Limit threads for source fetching
thread_limit_fetch = 8
```

- To fetch us all the sources:
```bash
python3 prohacktive_fetch.py
```
This will download all the database from different +100 sources into a folder called ```tmp/fetched_srcs/``` inside the repository that you have cloned.

It can take up to 30 minutes to fetching us all the sources

- To full update all the sources to the MongoDB database:
```bash
python3 prohacktive_full_update.py
```
This will read all the sources fetched inside ```tmp/fetched_srcs/``` directory, and insert all exploits & erase old exploits inside the database.

- Syncing incoming

It can take up to 15 minutes

This will also for each sources creates a collection inside your database

- For helping the analyzing/parsing of a JSON file for the sources that have been fetched you can use this python script this way in a terminal:

```bash
python3 json_analyzer.py <path to file>
...
python3 json_analyzer.py tmp/fetched_srcs/Vulners_cve
```

## Adding more sources

You can add more sources to the ```srcs/``` folder by writing a python module.

In order to get proper data, you'll need to write the parsed database from the source (can be different format) and convert it into a JSON file so the source manager can insert it into the MongoDB database in a new collections for you.

The function that the source manager that will call by importing your python module is called ```fetch_handler()``` and the future sources needs to be written into ```tmp/fetched_src/``` so the source manager can read all the fetched sources without taking too much RAM.
