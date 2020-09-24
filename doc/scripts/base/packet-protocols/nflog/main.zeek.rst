:tocdepth: 3

base/packet-protocols/nflog/main.zeek
=====================================
.. zeek:namespace:: PacketAnalyzer::NFLOG


:Namespace: PacketAnalyzer::NFLOG

Summary
~~~~~~~
Redefinable Options
###################
============================================================================================================ ===================
:zeek:id:`PacketAnalyzer::NFLOG::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` Identifier mappings
============================================================================================================ ===================

Redefinitions
#############
============================================================================================================ =
:zeek:id:`PacketAnalyzer::NFLOG::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` 
============================================================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::NFLOG::dispatch_map

   :Type: :zeek:type:`PacketAnalyzer::DispatchMap`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/packet-protocols/nflog/main.zeek`

      ``+=``::

         PacketAnalyzer::NFLOG::AF_INET = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IPV4] to record { analyzer:enum; }), PacketAnalyzer::NFLOG::AF_INET6 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IPV6] to record { analyzer:enum; })


   Identifier mappings


