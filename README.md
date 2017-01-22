fess_up
=======

Fess Up is an unintelligent DNS record guesser in Python. It offers
both a library and a command-line tool to scan specific domains for
(currently) one layer of subdomains. The scan is dictionary-based and
it will attempt to avoid superfluous queries by basing subsequent
queries off of previously discovered records.

fess_up's scanning wordlist is based on files installed in the
fess_up/dnsnames/ directory. To expand this list, either edit
`default.txt` or add another .txt file to the directory and it
will be automatically loaded.

Command-line tool
-------

To scan a domain using the `fess_up.py` (installed as
`fess_up` when using the Debian package) command line tool, simply
provide the domain as an argument:

```
fess_up nosmo.me
nosmo.me
{'@': {'A': ['92.51.245.61'],
        'MX': [('nosmo.me.', 10)],
        'TXT': ['v=spf1 mx -all']},
 'www': {'A': ['92.51.245.61'],
        'CNAME': ['nosmo.me.'],
        'MX': [('nosmo.me.', 10)],
        'TXT': ['v=spf1 mx -all']}}
```
`fess_up` can also output in a bind-like fashion when using the -B flag.

```
fess_up.py nosmo.me -B
nosmo.me
@       IN      A       92.51.245.61
@       IN      TXT     v=spf1 mx -all
@       IN      MX      10      nosmo.me.
www     IN      A       92.51.245.61
www     IN      CNAME   nosmo.me.
www     IN      MX      10      nosmo.me.
www     IN      TXT     v=spf1 mx -all
```

Library
--------

`fess_up`'s domain scan can be used as a library:

```
>>> from fess_up import dnsnames, DomainScan
>>> domain_scanner = DomainScan("nosmo.me", dnsnames.dnsnames)
>>> domain_scanner.runScan()
>>> dict(domain_scanner.data)
{'www': {'A': ['92.51.245.61'], 'CNAME': ['nosmo.me.'], 'MX': [('nosmo.me.', 10)], 'TXT': ['v=spf1 mx -all']}, None: {'A': ['92.51.245.61'], 'TXT': ['v=spf1 mx -all'], 'MX': [('nosmo.me.', 10)]}}
```
