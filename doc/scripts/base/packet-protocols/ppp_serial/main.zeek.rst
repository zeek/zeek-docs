:tocdepth: 3

base/packet-protocols/ppp_serial/main.zeek
==========================================
.. zeek:namespace:: PacketAnalyzer::PPP_SERIAL


:Namespace: PacketAnalyzer::PPP_SERIAL

Summary
~~~~~~~
Redefinable Options
###################
================================================================================================================= ===================
:zeek:id:`PacketAnalyzer::PPP_SERIAL::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` Identifier mappings
================================================================================================================= ===================

Redefinitions
#############
================================================================================================================= =
:zeek:id:`PacketAnalyzer::PPP_SERIAL::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` 
:zeek:id:`PacketAnalyzer::ROOT::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef`       
================================================================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::PPP_SERIAL::dispatch_map

   :Type: :zeek:type:`PacketAnalyzer::DispatchMap`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/packet-protocols/ppp_serial/main.zeek`

      ``+=``::

         641 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_MPLS] to record { analyzer:enum; }), 33 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IP] to record { analyzer:enum; }), 87 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IP] to record { analyzer:enum; })


   Identifier mappings


