Packet Analyzers
================

.. zeek:type:: PacketAnalyzer::Tag

   :Type: :zeek:type:`enum`

      .. zeek:enum:: PacketAnalyzer::ANALYZER_ARP PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_ETHERNET PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_FDDI PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_GRE PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_IEEE802_11 PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_IEEE802_11_RADIO PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_IP PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_IPTUNNEL PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_LINUXSLL PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_MPLS PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_NFLOG PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_NULL PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_PPPOE PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_PPPSERIAL PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_ROOT PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_SKIP PacketAnalyzer::Tag

      .. zeek:enum:: PacketAnalyzer::ANALYZER_VLAN PacketAnalyzer::Tag

Zeek::ARP
---------

ARP packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_ARP`

Events
++++++

.. zeek:id:: arp_request

   :Type: :zeek:type:`event` (mac_src: :zeek:type:`string`, mac_dst: :zeek:type:`string`, SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`)

   Generated for ARP requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :mac_src: The request's source MAC address.
   

   :mac_dst: The request's destination MAC address.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   
   .. zeek:see:: arp_reply  bad_arp

.. zeek:id:: arp_reply

   :Type: :zeek:type:`event` (mac_src: :zeek:type:`string`, mac_dst: :zeek:type:`string`, SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`)

   Generated for ARP replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :mac_src: The reply's source MAC address.
   

   :mac_dst: The reply's destination MAC address.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   
   .. zeek:see::  arp_request bad_arp

.. zeek:id:: bad_arp

   :Type: :zeek:type:`event` (SPA: :zeek:type:`addr`, SHA: :zeek:type:`string`, TPA: :zeek:type:`addr`, THA: :zeek:type:`string`, explanation: :zeek:type:`string`)

   Generated for ARP packets that Zeek cannot interpret. Examples are packets
   with non-standard hardware address formats or hardware addresses that do not
   match the originator of the packet.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   

   :explanation: A short description of why the ARP packet is considered "bad".
   
   .. zeek:see:: arp_reply arp_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

Zeek::Ethernet
--------------

Ethernet packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_ETHERNET`

Zeek::FDDI
----------

FDDI packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_FDDI`

Zeek::GRE
---------

GRE packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_GRE`

Zeek::IEEE802_11
----------------

IEEE 802.11 packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_IEEE802_11`

Zeek::IEEE802_11_Radio
----------------------

IEEE 802.11 Radiotap packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_IEEE802_11_RADIO`

Zeek::IP
--------

Packet analyzer for IP fallback (v4 or v6)

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_IP`

Zeek::IPTunnel
--------------

IPTunnel packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_IPTUNNEL`

Zeek::LinuxSLL
--------------

Linux cooked capture (SLL) packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_LINUXSLL`

Zeek::MPLS
----------

MPLS packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_MPLS`

Zeek::NFLog
-----------

NFLog packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_NFLOG`

Zeek::Null
----------

Null packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_NULL`

Zeek::PPPoE
-----------

PPPoE packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_PPPOE`

Zeek::PPPSerial
---------------

PPPSerial packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_PPPSERIAL`

Zeek::Root
----------

Root packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_ROOT`

Zeek::Skip
----------

Skip packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_SKIP`

Zeek::VLAN
----------

VLAN packet analyzer

Components
++++++++++

:zeek:enum:`PacketAnalyzer::ANALYZER_VLAN`

