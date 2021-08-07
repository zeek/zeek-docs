:tocdepth: 3

base/bif/packet_analysis.bif.zeek
=================================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: PacketAnalyzer


:Namespaces: GLOBAL, PacketAnalyzer

Summary
~~~~~~~
Functions
#########
====================================================================================== ==============================================================================================================
:zeek:id:`PacketAnalyzer::__set_ignore_checksums_nets`: :zeek:type:`function`          Internal function that is used to update the core-mirror of the script-level `ignore_checksums_nets` variable.
:zeek:id:`PacketAnalyzer::register_packet_analyzer`: :zeek:type:`function`             Add an entry to parent's dispatcher that maps a protocol/index to a next-stage child analyzer.
:zeek:id:`PacketAnalyzer::try_register_packet_analyzer_by_name`: :zeek:type:`function` Attempts to add an entry to `parent`'s dispatcher that maps a protocol/index to a next-stage `child` analyzer.
====================================================================================== ==============================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: PacketAnalyzer::__set_ignore_checksums_nets
   :source-code: base/bif/packet_analysis.bif.zeek 29 29

   :Type: :zeek:type:`function` (v: :zeek:type:`subnet_set`) : :zeek:type:`bool`

   Internal function that is used to update the core-mirror of the script-level `ignore_checksums_nets` variable.

.. zeek:id:: PacketAnalyzer::register_packet_analyzer
   :source-code: base/bif/packet_analysis.bif.zeek 15 15

   :Type: :zeek:type:`function` (parent: :zeek:type:`PacketAnalyzer::Tag`, identifier: :zeek:type:`count`, child: :zeek:type:`PacketAnalyzer::Tag`) : :zeek:type:`bool`

   Add an entry to parent's dispatcher that maps a protocol/index to a next-stage child analyzer.
   

   :parent: The parent analyzer being modified

   :identifier: The identifier for the protocol being registered

   :child: The analyzer that will be called for the identifier
   

.. zeek:id:: PacketAnalyzer::try_register_packet_analyzer_by_name
   :source-code: base/bif/packet_analysis.bif.zeek 25 25

   :Type: :zeek:type:`function` (parent: :zeek:type:`string`, identifier: :zeek:type:`count`, child: :zeek:type:`string`) : :zeek:type:`bool`

   Attempts to add an entry to `parent`'s dispatcher that maps a protocol/index to a next-stage `child` analyzer.
   This may fail if either of the two names does not respond to a known analyzer.
   

   :parent: The parent analyzer being modified

   :identifier: The identifier for the protocol being registered

   :child: The analyzer that will be called for the identifier
   


