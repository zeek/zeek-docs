:tocdepth: 3

base/packet-protocols/ieee802_11/main.zeek
==========================================
.. zeek:namespace:: PacketAnalyzer::IEEE802_11


:Namespace: PacketAnalyzer::IEEE802_11

Summary
~~~~~~~
Redefinable Options
###################
================================================================================================================= ======================================
:zeek:id:`PacketAnalyzer::IEEE802_11::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` Identifier mappings based on EtherType
================================================================================================================= ======================================

Redefinitions
#############
================================================================================================================= =
:zeek:id:`PacketAnalyzer::IEEE802_11::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` 
================================================================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::IEEE802_11::dispatch_map

   :Type: :zeek:type:`PacketAnalyzer::DispatchMap`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/packet-protocols/ieee802_11/main.zeek`

      ``+=``::

         2048 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IPV4] to record { analyzer:enum; }), 34525 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IPV6] to record { analyzer:enum; }), 2054 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_ARP] to record { analyzer:enum; }), 32821 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_ARP] to record { analyzer:enum; })


   Identifier mappings based on EtherType


