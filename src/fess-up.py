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

import dns.resolver
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.IN.A
import dns.rdtypes.ANY.MX

import collections
import logging
import argparse
import yaml
import pprint

import dnsnames

try:
    import MySQLdb
    mysql_available = True
except ImportError as e:
    logging.warning("No MySQLdb module available, not using MySQL support")
    mysql_available = False

subdomain_list = ["www", "mail", "wiki", "search", "blog", "blogs", "sites", "my",
                  "www2", "dev", None]

# Here we use "None" to indicate the root of a domain.
dnsname_list = dnsnames.dnsnames + [None]

dnsobject_map = {
    dns.rdtypes.ANY.CNAME.CNAME: ["target"],
    dns.rdtypes.IN.A.A: ["address"],
    dns.rdtypes.ANY.MX.MX: ["exchange", "preference"]
    }

class DomainScan(object):

    def __init__(self, domain, subdomain_list):
        self.domain = domain
        self.subdomain_list = subdomain_list
        self.data = collections.defaultdict(dict)

    def runScan(self):

        if self._checkWildcards():
            sys.stderr.write(("Wildcard test returned positive - our results "
                              "will be tainted..."))

        for subdomain, record in self._scan("A").iteritems():
            self.data[subdomain]["A"] = record

        for subdomain in self.data.keys():
            for subdomain, records in self._scan("CNAME").iteritems():
                self.data[subdomain]["CNAME"] = [ str(record) for record in records ]

        mxlist = []
        for subdomain in self.data.keys():
            for subdomain, records in self._scan("MX").iteritems():
                for i in xrange(0, len(records), 2):
                    mxtuple = (str(records[i]), records[i+1])
                    if mxtuple not in mxlist:
                        mxlist.append(mxtuple)
        self.data[subdomain]["MX"] = mxlist

    def _scan(self, record_type, subdomains=None):
        results = collections.defaultdict(list)
        if not subdomains:
            subdomains = self.subdomain_list

        for subdomain in subdomains:
            query_str = "%s.%s" % (subdomain, self.domain) if subdomain else self.domain
            try:
                answers = dns.resolver.query("%s" % (query_str), record_type)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.name.EmptyLabel) as e:
                continue

            record_results = []
            for data in answers:
                record_valuenames = dnsobject_map[type(data)]
                for record_valuename in record_valuenames:
                    record_results.append(getattr(data, record_valuename))
            results[subdomain] = record_results

        return dict(results)

    def _checkWildcards(self):
        try:
            answers = dns.resolver.query(
                "trollllloolololoololo1337lolololololollol.%s" % self.domain
            )
        except dns.resolver.NXDOMAIN as e:
            return False
        except dns.resolver.NoAnswer:
            return False
        return True

def DatabaseDomainScan(DomainScan):
    def __init__(self, domain, subdomain_list, mysql_config):
        super(DomainScan, self).__init(domain, subdomain_list)
        if mysql_config:
            self.mysql_connection = MySQLdb.connection(mysql_config["host"],
                                                       mysql_config["user"],
                                                       mysql_config["pass"],
                                                       mysql_config["database"])
        else:
            self.mysql_connection = None

    def runScan(self):
        scan_results = super(DomainScan, self).runScan()

def main(domain_list, mysql_config):
    for domain in domain_list:
        print domain
        domain_scanner = DomainScan(domain, dnsname_list)
        domain_scanner.runScan()
        pprint.pprint(dict(domain_scanner.data))
        print

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan a domain for DNS records')

    parser.add_argument('domains', metavar='dom', type=str, nargs='+',
                        help='A list of domains to check')
    parser.add_argument('-c', dest = 'config_path', action = 'store',
                        default = '/etc/fess-up.yaml',
                        help = 'Path to config file.')
    args = parser.parse_args()

    config = yaml.load(open(args.config_path).read())

    mysql_config = {}
    for i in ["host", "database", "user", "pass"]:
        mysql_config[i] = config.get("mysql", {}).get(i, None)

    config_check = sum(map(lambda a: a is not None, ("Derp", "derp", "derp", "derp")))
    if config_check != 4 and config_check != 0:
        # config needs to be complete or not there at all
        raise Exception("MySQL configuration not complete!")

    if config_check == 4 and not mysql_available:
        raise Exception("MySQLdb module not present but MySQL is configured")

    main(args.domains, mysql_config)
