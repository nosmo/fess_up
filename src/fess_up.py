#!/usr/bin/env python

"""Simple DNS guessing script.
nosmo@nosmo.me || https://nosmo.me/~nosmo/

 This script currently checks for A, CNAME and MX records for a
particular domain, doing dumb guessing based on the subdomains in the
subdomain_list list.

This script differs to dnsgrind and subbrute in that it attempts to
get more than simply A or CNAME records. In the long run the plan is
to produce a script that can reproduce a relatively mundane zone file
in a really ham-fisted but complete way.

N(C) license.
"""

import logging
import argparse
import yaml
import pprint

from fess_up import dnsnames, DomainScan

try:
    import MySQLdb
    mysql_available = True
except ImportError as e:
    logging.warning("No MySQLdb module available, not using MySQL support")
    mysql_available = False

# Here we use "None" to indicate the root of a domain.
dnsname_list = dnsnames.dnsnames + [None]

def main(domain_list, mysql_config, atmode=False):
    for domain in domain_list:
        print domain
        domain_scanner = DomainScan(domain, dnsname_list)
        domain_scanner.runScan()
        if atmode and None in domain_scanner.data:
            domain_scanner.data["@"] = domain_scanner.data[None]
            del(domain_scanner.data[None])
        pprint.pprint(dict(domain_scanner.data))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan a domain for DNS records')

    parser.add_argument('domains', metavar='dom', type=str, nargs='+',
                        help='A list of domains to check')
    parser.add_argument("--at", dest="atmode", action="store_true",
                        help="Don't output None, use @ instead")
    parser.add_argument('-c', dest = 'config_path', action = 'store',
                        default='/etc/fess-up.yaml',
                        help='Path to config file.')
    args = parser.parse_args()

    config = yaml.load(open(args.config_path).read())

    mysql_config = {}
    for i in ["host", "database", "user", "pass"]:
        mysql_config[i] = config.get("mysql", {}).get(i, None)

    config_check = sum(map(lambda a: a is not None, mysql_config.values()))
    if config_check != 4 and config_check != 0:
        # config needs to be complete or not there at all
        raise Exception("MySQL configuration not complete!")

    if config_check == 4 and not mysql_available:
        raise Exception("MySQLdb module not present but MySQL is configured")

    main(args.domains, mysql_config, args.atmode)
