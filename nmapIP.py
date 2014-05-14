#! /usr/bin/python
"""
Requires python-libnmap[1], Maltego.py [2] from and the Shodan transforms [3] (for the "Shodan.Service" entity type we return). 
You don't need a Shodan API key for this transform to work, but it is useful.


[1] https://github.com/savon-noir/python-libnmap
[2] http://www.paterva.com/TRX_Ubuntu.tgz
[3] https://maltego.shodan.io/
"""

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import sys
from Maltego import *


def do_nmap_scan(target):
    ## create a transform object
    transform = MaltegoTransform()
    ## set the nmap options
    nm = NmapProcess(targets=target, options="-P0 -sT --host-timeout 3m")
    ## start the nmap scan
    nm.run()

    nmap_report = NmapParser.parse(nm.stdout)

    """ 
    more info on the nmap object available here:
    https://libnmap.readthedocs.org/en/latest/process.html

    """
    for host in nmap_report.hosts:
        for serv in host.services:
            ## for now we return a shodan service, so we can leverage of off the Shodan API
            transform.addEntity("Shodan.Service", "%s/%s" % (str(serv.port), serv.service))

    print transform.returnOutput()

do_nmap_scan(sys.argv[1])
