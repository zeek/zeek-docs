:tocdepth: 3

base/packet-protocols/root/main.zeek
====================================
.. zeek:namespace:: PacketAnalyzer::ROOT


:Namespace: PacketAnalyzer::ROOT

Summary
~~~~~~~
Redefinable Options
###################
=========================================================================================================== ===================================================================
:zeek:id:`PacketAnalyzer::ROOT::default_analyzer`: :zeek:type:`PacketAnalyzer::Tag` :zeek:attr:`&redef`     Default analyzer (if we don't know the link type, we assume raw IP)
:zeek:id:`PacketAnalyzer::ROOT::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` Identifier mappings based on link type
=========================================================================================================== ===================================================================

Redefinitions
#############
=========================================================================================================== =
:zeek:id:`PacketAnalyzer::ROOT::dispatch_map`: :zeek:type:`PacketAnalyzer::DispatchMap` :zeek:attr:`&redef` 
=========================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketAnalyzer::ROOT::default_analyzer

   :Type: :zeek:type:`PacketAnalyzer::Tag`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``PacketAnalyzer::ANALYZER_IP``

   Default analyzer (if we don't know the link type, we assume raw IP)

.. zeek:id:: PacketAnalyzer::ROOT::dispatch_map

   :Type: :zeek:type:`PacketAnalyzer::DispatchMap`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/packet-protocols/root/main.zeek`

      ``+=``::

         PacketAnalyzer::ROOT::DLT_EN10MB = (coerce [$analyzer=PacketAnalyzer::ANALYZER_ETHERNET] to record { analyzer:enum; }), PacketAnalyzer::ROOT::DLT_FDDI = (coerce [$analyzer=PacketAnalyzer::ANALYZER_FDDI] to record { analyzer:enum; }), PacketAnalyzer::ROOT::DLT_IEEE802_11 = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IEEE802_11] to record { analyzer:enum; }), PacketAnalyzer::ROOT::DLT_IEEE802_11_RADIO = (coerce [$analyzer=PacketAnalyzer::ANALYZER_IEEE802_11_RADIO] to record { analyzer:enum; }), PacketAnalyzer::ROOT::DLT_LINUX_SLL = (coerce [$analyzer=PacketAnalyzer::ANALYZER_LINUXSLL] to record { analyzer:enum; }), PacketAnalyzer::ROOT::DLT_NFLOG = (coerce [$analyzer=PacketAnalyzer::ANALYZER_NFLOG] to record { analyzer:enum; })

   :Redefinition: from :doc:`/scripts/base/packet-protocols/null/main.zeek`

      ``+=``::

         PacketAnalyzer::NULL::DLT_NULL = (coerce [$analyzer=PacketAnalyzer::ANALYZER_NULL] to record { analyzer:enum; })

   :Redefinition: from :doc:`/scripts/base/packet-protocols/ppp_serial/main.zeek`

      ``+=``::

         PacketAnalyzer::PPP_SERIAL::DLT_PPP_SERIAL = (coerce [$analyzer=PacketAnalyzer::ANALYZER_PPPSERIAL] to record { analyzer:enum; })


   Identifier mappings based on link type


