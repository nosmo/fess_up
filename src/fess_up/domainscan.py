import dns.resolver
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.IN.A
import dns.rdtypes.ANY.TXT
import dns.rdtypes.ANY.MX
import sys

import collections

dnsobject_map = {
    dns.rdtypes.ANY.CNAME.CNAME: ["target"],
    dns.rdtypes.IN.A.A: ["address"],
    dns.rdtypes.ANY.MX.MX: ["exchange", "preference"],
    dns.rdtypes.ANY.TXT.TXT: ["strings"],
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

        for subdomain, records in self._scan("CNAME", subdomains=self.data.keys()).iteritems():
            self.data[subdomain]["CNAME"] = [ str(record) for record in records ]

        mxlist = []
        for subdomain, records in self._scan("MX", subdomains=self.data.keys()).iteritems():
            for i in xrange(0, len(records), 2):
                mxtuple = (str(records[i]), records[i+1])
                if mxtuple not in mxlist:
                    mxlist.append(mxtuple)
            self.data[subdomain]["MX"] = mxlist

        for subdomain, records in self._scan("TXT", subdomains=self.data.keys()).iteritems():
            self.data[subdomain]["TXT"] = [ str(record) for record in records ]

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
