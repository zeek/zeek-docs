:tocdepth: 3

policy/frameworks/management/node/config.zeek
=============================================
.. zeek:namespace:: Management::Node

Configuration settings for nodes controlled by the Management framework.

:Namespace: Management::Node

Summary
~~~~~~~
Redefinable Options
###################
================================================================================ ========================
:zeek:id:`Management::Node::node_topic`: :zeek:type:`string` :zeek:attr:`&redef` The nodes' Broker topic.
================================================================================ ========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Management::Node::node_topic
   :source-code: policy/frameworks/management/node/config.zeek 8 8

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/management/node"``

   The nodes' Broker topic. Cluster nodes automatically subscribe
   to it, to receive request events from the Management framework.


