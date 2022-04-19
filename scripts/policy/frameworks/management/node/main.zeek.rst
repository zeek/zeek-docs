:tocdepth: 3

policy/frameworks/management/node/main.zeek
===========================================
.. zeek:namespace:: Management::Node

This module provides Management framework functionality present in every
cluster node, to allowing Management agents to interact with the nodes.

:Namespace: Management::Node
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`policy/frameworks/management/agent/config.zeek </scripts/policy/frameworks/management/agent/config.zeek>`, :doc:`policy/frameworks/management/log.zeek </scripts/policy/frameworks/management/log.zeek>`, :doc:`policy/frameworks/management/node/api.zeek </scripts/policy/frameworks/management/node/api.zeek>`, :doc:`policy/frameworks/management/node/config.zeek </scripts/policy/frameworks/management/node/config.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=================================================================================== =
:zeek:id:`Management::Log::role`: :zeek:type:`Management::Role` :zeek:attr:`&redef` 
=================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

