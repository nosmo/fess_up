import os
from setuptools import setup

setup(
    name = "fess_up",
    version = "1.1.3",
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
    install_requires=['PyYAML'],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Utilities",
        ],
    scripts = ["bin/fess_up"],
    )
