import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "fess_up",
    version = "1.0.0",
    author = "Hugh Nowlan",
    author_email = "nosmo@nosmo.me",
    description = "DNS record scraper",
    license = "N(C)",
    keywords = "dns zone scraper",
    url = "http://github.com/nosmo/fess_up",
    packages=['fess_up', 'fess_up.dnsnames'],
    long_description=read('../README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: N(C) License",
        ],
    scripts = ["fess_up.py"],
    data_files=[
        ('/etc', ["../conf/fess_up.yaml"]),
        ],
    )
