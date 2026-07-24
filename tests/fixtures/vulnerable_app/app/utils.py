"""Misc helpers. (Intentionally vulnerable fixture.)"""

import pickle
import subprocess

import requests


def calculate(expression: str):
    # TLX-C002: eval on user input
    return eval(expression)


def load_session(blob: bytes):
    # TLX-C003: pickle deserialization of untrusted data
    return pickle.loads(blob)


def ping_host(host: str):
    # TLX-C004: shell=True with a non-literal command
    return subprocess.run(f"ping -n 1 {host}", shell=True, capture_output=True)


def fetch_status(url: str):
    # TLX-C007: TLS verification disabled
    return requests.get(url, verify=False, timeout=5)
