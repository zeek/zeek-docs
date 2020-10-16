:tocdepth: 3

base/packet-protocols/null/main.zeek
====================================
.. zeek:namespace:: PacketAnalyzer::NULL


:Namespace: PacketAnalyzer::NULL

Summary
~~~~~~~
Redefinable Options
###################
=========================================================================================================== ===================
:zeek:id:`PacketAnalyzer::NULL::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` Identifier mappings
=========================================================================================================== ===================

Redefinitions
#############
=========================================================================================================== =============================================================================
:zeek:id:`PacketAnalyzer::NULL::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` From the Wireshark Wiki: AF_INET6ANALYZER, unfortunately, has different
                                                                                                            values in {NetBSD,OpenBSD,BSD/OS}, {FreeBSD,DragonFlyBSD}, and
                                                                                                            {Darwin/macOS}, so an IPv6 packet might have a link-layer header with 24, 28,
                                                                                                            or 30 as the ``AF_`` value.
:zeek:id:`PacketAnalyzer::ROOT::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` 
=========================================================================================================== =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::NULL::dispatch_map

   :Type: :zeek:type:`PacketAnalyzer::DispatchMap`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/packet-protocols/null/main.zeek`

      ``+=``::

         2 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IP] to record { analyzer:enum; }), 24 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IP] to record { analyzer:enum; }), 28 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IP] to record { analyzer:enum; }), 30 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IP] to record { analyzer:enum; })


   Identifier mappings


