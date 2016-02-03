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

dnsname_list = dnsnames.dnsnames

def main(domain_list, bindmode=False):
    for domain in domain_list:
        print domain
        domain_scanner = DomainScan(domain, dnsname_list)
        domain_scanner.runScan()
        if None in domain_scanner.data:
            domain_scanner.data["@"] = domain_scanner.data[None]
            del(domain_scanner.data[None])
        if bindmode:
            for label, recorddict in domain_scanner.data.iteritems():
                for recordtype, recordvalues in recorddict.iteritems():
                    arglist = reduce(lambda a,b: a+b, recordvalues)
                    if recordtype == "MX":
                        arglist = "%s\t%s" % (arglist[1], arglist[0])
                    print "%s\t%s\t%s\t%s" % (label, "IN",
                                              recordtype,
                                              arglist)
        else:
            pprint.pprint(dict(domain_scanner.data))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan a domain for DNS records')

    parser.add_argument('domains', metavar='dom', type=str, nargs='+',
                        help='A list of domains to check')
    parser.add_argument("--bind", "-B", dest="bindmode", action="store_true",
                        help="Output in a bind-like manner")
    args = parser.parse_args()

    main(args.domains, args.bindmode)
