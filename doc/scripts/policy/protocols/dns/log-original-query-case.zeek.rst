:tocdepth: 3

policy/protocols/dns/log-original-query-case.zeek
=================================================
.. zeek:namespace:: DNS

This script adds the query with its original letter casing
to the DNS log.

:Namespace: DNS
:Imports: :doc:`base/protocols/dns/main.zeek </scripts/base/protocols/dns/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== =
:zeek:type:`DNS::Info`: :zeek:type:`record` 
=========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

