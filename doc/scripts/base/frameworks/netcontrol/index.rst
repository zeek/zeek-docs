:orphan:

Package: base/frameworks/netcontrol
===================================

The NetControl framework provides a way for Bro to interact with networking
hard- and software, e.g. for dropping and shunting IP addresses/connections,
etc.

:doc:`/scripts/base/frameworks/netcontrol/__load__.bro`


:doc:`/scripts/base/frameworks/netcontrol/types.bro`

   This file defines the types that are used by the NetControl framework.
   
   The most important type defined in this file is :bro:see:`NetControl::Rule`,
   which is used to describe all rules that can be expressed by the NetControl framework. 

:doc:`/scripts/base/frameworks/netcontrol/main.bro`

   Bro's NetControl framework.
   
   This plugin-based framework allows to control the traffic that Bro monitors
   as well as, if having access to the forwarding path, the traffic the network
   forwards. By default, the framework lets everything through, to both Bro
   itself as well as on the network. Scripts can then add rules to impose
   restrictions on entities, such as specific connections or IP addresses.
   
   This framework has two APIs: a high-level and low-level. The high-level API
   provides convenience functions for a set of common operations. The
   low-level API provides full flexibility.

:doc:`/scripts/base/frameworks/netcontrol/plugin.bro`

   This file defines the plugin interface for NetControl.

:doc:`/scripts/base/frameworks/netcontrol/plugins/__load__.bro`


:doc:`/scripts/base/frameworks/netcontrol/plugins/debug.bro`

   Debugging plugin for the NetControl framework, providing insight into
   executed operations.

:doc:`/scripts/base/frameworks/netcontrol/plugins/openflow.bro`

   OpenFlow plugin for the NetControl framework.

:doc:`/scripts/base/frameworks/netcontrol/plugins/packetfilter.bro`

   NetControl plugin for the process-level PacketFilter that comes with
   Bro. Since the PacketFilter in Bro is quite limited in scope
   and can only add/remove filters for addresses, this is quite
   limited in scope at the moment. 

:doc:`/scripts/base/frameworks/netcontrol/plugins/broker.bro`

   Broker plugin for the NetControl framework. Sends the raw data structures
   used in NetControl on to Broker to allow for easy handling, e.g., of
   command-line scripts.

:doc:`/scripts/base/frameworks/netcontrol/plugins/acld.bro`

   Acld plugin for the netcontrol framework.

:doc:`/scripts/base/frameworks/netcontrol/drop.bro`

   Implementation of the drop functionality for NetControl.

:doc:`/scripts/base/frameworks/netcontrol/shunt.bro`

   Implementation of the shunt functionality for NetControl.

:doc:`/scripts/base/frameworks/netcontrol/catch-and-release.bro`

   Implementation of catch-and-release functionality for NetControl.

:doc:`/scripts/base/frameworks/netcontrol/non-cluster.bro`


