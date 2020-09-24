:tocdepth: 3

base/packet-protocols/ethernet/main.zeek
========================================
.. zeek:namespace:: PacketAnalyzer::ETHERNET


:Namespace: PacketAnalyzer::ETHERNET

Summary
~~~~~~~
Redefinable Options
###################
=============================================================================================================== ======================================
:zeek:id:`PacketAnalyzer::ETHERNET::default_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef`     Default analyzer
:zeek:id:`PacketAnalyzer::ETHERNET::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` Identifier mappings based on EtherType
:zeek:id:`PacketAnalyzer::ETHERNET::llc_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef`         IEEE 802.2 LLC analyzer
:zeek:id:`PacketAnalyzer::ETHERNET::novell_raw_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef`  Novell raw IEEE 802.3 analyzer
:zeek:id:`PacketAnalyzer::ETHERNET::snap_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef`        IEEE 802.2 SNAP analyzer
=============================================================================================================== ======================================

Redefinitions
#############
=============================================================================================================== =
:zeek:id:`PacketAnalyzer::ETHERNET::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` 
=============================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::ETHERNET::default_analyzer

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PacketAnalyzer::ANALYZER_IP``

   Default analyzer

.. zeek:id:: PacketAnalyzer::ETHERNET::dispatch_map

   :Type: :zeek:type:`PacketAnalyzer::DispatchMap`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/packet-protocols/ethernet/main.zeek`

      ``+=``::

         34887 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_MPLS] to record { analyzer:enum; }), 2048 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IPV4] to record { analyzer:enum; }), 34525 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IPV6] to record { analyzer:enum; }), 2054 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_ARP] to record { analyzer:enum; }), 32821 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_ARP] to record { analyzer:enum; }), 33024 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_VLAN] to record { analyzer:enum; }), 34984 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_VLAN] to record { analyzer:enum; }), 37120 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_VLAN] to record { analyzer:enum; }), 34916 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_PPPOE] to record { analyzer:enum; })


   Identifier mappings based on EtherType

.. zeek:id:: PacketAnalyzer::ETHERNET::llc_analyzer

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`

   IEEE 802.2 LLC analyzer

.. zeek:id:: PacketAnalyzer::ETHERNET::novell_raw_analyzer

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`

   Novell raw IEEE 802.3 analyzer

.. zeek:id:: PacketAnalyzer::ETHERNET::snap_analyzer

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`

   IEEE 802.2 SNAP analyzer


