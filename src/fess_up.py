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
import dns.rdtypes.ANY.TXT
import dns.rdtypes.ANY.MX

import collections
import logging
import argparse
import yaml
import pprint
import sys

import Queue

import dnsnames

try:
    import MySQLdb
    mysql_available = True
except ImportError as e:
    logging.warning("No MySQLdb module available, not using MySQL support")
    mysql_available = False

# Here we use "None" to indicate the root of a domain.
dnsname_list = dnsnames.dnsnames + [None]

dnsobject_map = {
    dns.rdtypes.ANY.CNAME.CNAME: ["target"],
    dns.rdtypes.IN.A.A: ["address"],
    dns.rdtypes.ANY.MX.MX: ["exchange", "preference"],
    dns.rdtypes.ANY.TXT.TXT: ["strings"],
    }

class RecordScanner(threading.Thread):

    def __init__(self, domain, subdomain_list, record_type, record_queue):
        self.domain = domain
        self.subdomain_list = subdomain_list
        self.record_type = record_type
        self.record_queue = record_queue

    def scanCNAME(self):
        for subdomain, records in self.scan("CNAME",
                                            self.domain,
                                            self.subdomain_list,
                                            self.record_queue).iteritems():
            self.record_queue.put((subdomain, "CNAME", [ str(record) for record in records ]))

    def scanMX(self):
        for subdomain, records in self.scan("MX",
                                            self.domain,
                                            self.subdomain_list,
                                            self.record_queue).iteritems():
            mxlist = []
            for i in xrange(0, len(records), 2):
                    mxtuple = (str(records[i]), records[i+1])
                    if mxtuple not in mxlist:
                        mxlist.append(mxtuple)
            self.record_queue.put((subdomain, "MX", mxlist))

    @staticmethod
    def scan(record_type, domain, subdomains, queue=None):
        results = collections.defaultdict(list)

        for subdomain in subdomains:
            query_str = "%s.%s" % (subdomain, domain) if subdomain else domain
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

    @staticmethod
    def checkWildcard(domain):
        try:
            answers = dns.resolver.query(
                "trollllloolololoololo1337lolololololollol.%s" % domain
            )
        except dns.resolver.NXDOMAIN as e:
            return False
        except dns.resolver.NoAnswer:
            return False
        return True

class DomainScan(object):

    def __init__(self, domain, subdomain_list):
        self.domain = domain
        self.subdomain_list = subdomain_list
        self.data = collections.defaultdict(dict)
        self.records_queue = Queue.Queue()
        self.wildcard_domain = False
        self.scanners = []

    def runScan(self):

        if RecordScanner.checkWildcard():
            self.wildcard_domain = True
            sys.stderr.write(("Wildcard test returned positive - our results "
                              "will be tainted..."))

        # Do a manual non-threaded scan here so that we have a more
        # accurate subdomain list
        for subdomain, record in RecordScanner.scan("A",
                                                    self.domain,
                                                    self.subdomain_list).iteritems():
            self.data[subdomain]["A"] = record

        scanners = []

        for record_type in ["CNAME", "MX", "TXT"]:
            scanner = RecordScanner(self.domain, self.data.keys(),
                                    record_type, self.records_queue)
            scanner.start()
            scanners.append(scanner)


        for subdomain in self.data.keys():
            for subdomain, records in self.scan("TXT").iteritems():
                self.data[subdomain]["TXT"] = [ str(record) for record in records ]


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
        domain_scanner = DomainScan(domain, dnsname_list)
        domain_scanner.runScan()

        print domain
        pprint.pprint(dict(domain_scanner.data))
        print

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan a domain for DNS records')

    parser.add_argument('domains', metavar='dom', type=str, nargs='+',
                        help='A list of domains to check')
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

    main(args.domains, mysql_config)
