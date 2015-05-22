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
    version = "1.1.1",
    author = "Hugh Nowlan",
    author_email = "nosmo@nosmo.me",
    description = "DNS record scraper",
    long_description = """Fess Up is an unintelligent DNS record
guesser. It offers both a library and a command line tool to scan
specific domains for (currently) one layer of subdomains. The scan is
dictionary based and it will attempt to avoid superfluous queries by
basing subsequent queries off of previously discovered records.
""",
    license = "Hacktivismo Enhanced-Source Software License Agreement",
    keywords = "dns zone scraper",
    url = "http://github.com/nosmo/fess_up",
    packages=['fess_up', 'fess_up.dnsnames'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Utilities",
        ],
    scripts = ["fess_up.py"],
    )
