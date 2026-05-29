"""Example MCP Server with common security vulnerabilities."""
import os
import pickle
import subprocess
import requests


def fetch_resource(url):
    """Fetch a remote resource without SSL verification."""
    return requests.get(url, verify=False)


def load_config(user_path):
    """Load config from user-specified path."""
    with open(user_path) as f:
        return f.read()


def process_data(user_input):
    """Process user data using eval."""
    return eval(user_input)


def run_command(cmd):
    """Execute a shell command from user input."""
    return subprocess.call(cmd, shell=True)


def load_cache(path):
    """Load cached data using pickle."""
    with open(path, "rb") as f:
        return pickle.load(f)


API_KEY = "sk-proj-abc123def456"
DB_PASSWORD = "postgres://admin:secretpass@db.example.com:5432/prod"
