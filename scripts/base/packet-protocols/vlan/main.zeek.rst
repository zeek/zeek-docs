:tocdepth: 3

base/packet-protocols/vlan/main.zeek
====================================
.. zeek:namespace:: PacketAnalyzer::VLAN


:Namespace: PacketAnalyzer::VLAN

Summary
~~~~~~~
Redefinable Options
###################
=========================================================================================================== ======================================
:zeek:id:`PacketAnalyzer::VLAN::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` Identifier mappings based on EtherType
=========================================================================================================== ======================================

Redefinitions
#############
=========================================================================================================== =
:zeek:id:`PacketAnalyzer::VLAN::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` 
=========================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::VLAN::dispatch_map

   :Type: :zeek:type:`PacketAnalyzer::DispatchMap`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/packet-protocols/vlan/main.zeek`

      ``+=``::

         34887 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_MPLS] to record { analyzer:enum; }), 2048 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IP] to record { analyzer:enum; }), 34525 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IP] to record { analyzer:enum; }), 2054 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_ARP] to record { analyzer:enum; }), 32821 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_ARP] to record { analyzer:enum; }), 33024 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_VLAN] to record { analyzer:enum; }), 34916 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_PPPOE] to record { analyzer:enum; })


   Identifier mappings based on EtherType


