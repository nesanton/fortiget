# fortiget
CLI query tools for Fortinet Fortigate firewalls

Currently in rewrite. Existing code is ugly and hardly usefull to anybody.


OBSOLETE_fortiget.py
-----------
```
Usage: fortiget.py <firewall_ip> <space separated portlist>
```
Prints everything you'd like to know about  a firewall's port.  Settings,  Routes,  Policies.

Dependencies:
* python2.6
* pxssh
* prettytable



OBSOLETE_fortigetX.py
------------
```
Usage: fortigetX.py <firewall_ip>
```
Dumps all the policies and firewall objects into xslx spreadsheet. Resolves all named objects to  their values

Dependencies:
* python2.6
* pxssh
* openpyxl
