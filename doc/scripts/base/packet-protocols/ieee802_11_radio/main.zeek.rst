:tocdepth: 3

base/packet-protocols/ieee802_11_radio/main.zeek
================================================
.. zeek:namespace:: PacketAnalyzer::IEEE802_11_RADIO


:Namespace: PacketAnalyzer::IEEE802_11_RADIO

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================================================= ===================
:zeek:id:`PacketAnalyzer::IEEE802_11_RADIO::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` Identifier mappings
======================================================================================================================= ===================

Redefinitions
#############
======================================================================================================================= =
:zeek:id:`PacketAnalyzer::IEEE802_11_RADIO::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` 
======================================================================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::IEEE802_11_RADIO::dispatch_map

   :Type: :zeek:type:`PacketAnalyzer::DispatchMap`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/packet-protocols/ieee802_11_radio/main.zeek`

      ``+=``::

         PacketAnalyzer::IEEE802_11_RADIO::DLT_IEEE802_11 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IEEE802_11] to record { analyzer:enum; })


   Identifier mappings


