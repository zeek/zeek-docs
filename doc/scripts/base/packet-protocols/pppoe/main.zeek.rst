:tocdepth: 3

base/packet-protocols/pppoe/main.zeek
=====================================
.. zeek:namespace:: PacketAnalyzer::PPPOE


:Namespace: PacketAnalyzer::PPPOE

Summary
~~~~~~~
Redefinable Options
###################
============================================================================================================ ===================
:zeek:id:`PacketAnalyzer::PPPOE::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` Identifier mappings
============================================================================================================ ===================

Redefinitions
#############
============================================================================================================ =
:zeek:id:`PacketAnalyzer::PPPOE::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` 
============================================================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::PPPOE::dispatch_map

   :Type: :zeek:type:`PacketAnalyzer::DispatchMap`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/packet-protocols/pppoe/main.zeek`

      ``+=``::

         33 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IPV4] to record { analyzer:enum; }), 87 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IPV6] to record { analyzer:enum; })


   Identifier mappings


