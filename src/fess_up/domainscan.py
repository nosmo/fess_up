import dns.resolver
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.IN.A
import dns.rdtypes.ANY.TXT
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.MX
import sys

import collections

dnsobject_map = {
    dns.rdtypes.ANY.CNAME.CNAME: ["target"],
    dns.rdtypes.IN.A.A: ["address"],
    dns.rdtypes.ANY.MX.MX: ["exchange", "preference"],
    dns.rdtypes.ANY.TXT.TXT: ["strings"],
    dns.rdtypes.ANY.NS.NS: ["target"],
    }

class DomainScan(object):

    def __init__(self, domain, subdomain_list):
        self.domain = domain
        self.subdomain_list = subdomain_list
        self.data = collections.defaultdict(dict)
        self.resolver = dns.resolver.Resolver()
        self.resolver.retry_servfail = True
        self.wildcard = False

    def runScan(self):

        if self._checkWildcards():
            sys.stderr.write(("Wildcard test returned positive - our results "
                              "will be tainted..."))
            self.wildcard = True

        for subdomain, record in self._scan("NS").iteritems():
            self.data[subdomain]["NS"] = record

        for subdomain, record in self._scan("A").iteritems():
            self.data[subdomain]["A"] = record

        for subdomain, records in self._scan("CNAME").iteritems():
            self.data[subdomain]["CNAME"] = [ str(record) for record in records ]

        mxlist = []
        for subdomain, records in self._scan("MX", subdomains=self.data.keys()).iteritems():
            for i in xrange(0, len(records), 2):
                mxtuple = (str(records[i]), records[i+1])
                if mxtuple not in mxlist:
                    mxlist.append(mxtuple)
            self.data[subdomain]["MX"] = mxlist

        for subdomain, records in self._scan("TXT", subdomains=self.data.keys()).iteritems():
            self.data[subdomain]["TXT"] = records

    def _scan(self, record_type, subdomains=None):
        results = collections.defaultdict(list)
        if not subdomains:
            subdomains = self.subdomain_list

        for subdomain in subdomains:
            query_str = "%s.%s" % (subdomain, self.domain) if subdomain else self.domain
            try:
                answers = self.resolver.query("%s" % (query_str), record_type)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.name.EmptyLabel) as e:
                continue

            # Skip CNAME records when we haven't asked for them
            if answers.qname != answers.canonical_name:
                continue

            record_results = []
            for data in answers:
                record_valuenames = dnsobject_map[type(data)]
                for record_valuename in record_valuenames:
                    record_data = getattr(data, record_valuename)
                    if type(record_data) == list:
                        record_results += record_data
                    else:
                        record_results.append(str(record_data))
            results[subdomain] = record_results

        return dict(results)

    def _checkWildcards(self):
        try:
            answers = self.resolver.query(
                "trollllloolololoololo1337lolololololollol.%s" % self.domain
            )
        except dns.resolver.NXDOMAIN as e:
            return False
        except dns.resolver.NoAnswer:
            return False
        return True
