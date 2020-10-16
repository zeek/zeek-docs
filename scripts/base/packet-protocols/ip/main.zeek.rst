:tocdepth: 3

base/packet-protocols/ip/main.zeek
==================================
.. zeek:namespace:: PacketAnalyzer::IP


:Namespace: PacketAnalyzer::IP

Summary
~~~~~~~
Redefinable Options
###################
========================================================================================================= ================================================
:zeek:id:`PacketAnalyzer::IP::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` Identifier mappings based on IP version (4 or 6)
========================================================================================================= ================================================

Redefinitions
#############
========================================================================================================= =
:zeek:id:`PacketAnalyzer::IP::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` 
========================================================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::IP::dispatch_map

   :Type: :zeek:type:`PacketAnalyzer::DispatchMap`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/packet-protocols/ip/main.zeek`

      ``+=``::

         4 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IPTUNNEL] to record { analyzer:enum; }), 41 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IPTUNNEL] to record { analyzer:enum; }), 47 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_GRE] to record { analyzer:enum; })


   Identifier mappings based on IP version (4 or 6)


