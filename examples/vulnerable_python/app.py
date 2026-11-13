# INTENTIONALLY INSECURE: this file must never be deployed, imported or run.
# It exists only so the ReconMind code scan has known findings for demos and tests.
# Every function below has a vulnerability on purpose.
import hashlib
import pickle
import sqlite3
import subprocess

import yaml

DB_PASSWORD = "SuperSecret123"


def find_user(username):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE name = '%s'" % username
    return conn.execute(query).fetchall()


def ping(host):
    return subprocess.check_output("ping -c 1 " + host, shell=True)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def load_config(text):
    return yaml.load(text)


def load_session(data):
    return pickle.loads(data)
