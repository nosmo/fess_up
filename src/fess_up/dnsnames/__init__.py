import os
import glob

dnsnames = []
dnsname_list = ["www", "mail", "wiki", "search", "blog", "blogs", "sites", "my", "m"
                  "www2", "dev", None]
dnsnames += dnsname_list

if os.path.isfile("/usr/share/i18n/SUPPORTED"):
    country_codes = []
    with open("/usr/share/i18n/SUPPORTED") as locales_f:
        locale_data = locales_f.readlines()
        for line in locale_data:
            country_codes.append(line.strip().split("_")[0].lower())
    dnsnames += set(country_codes)

for txtfile in glob.glob("%s/*.txt" % os.path.dirname(os.path.abspath(__file__))):
    with open(txtfile) as wordfile:
        dnsnames += [ i.strip() for i in wordfile.readlines() if i.strip() ]
