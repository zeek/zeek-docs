:tocdepth: 3

base/protocols/quic/main.zeek
=============================
.. zeek:namespace:: QUIC

Initial idea for a quic.log.

:Namespace: QUIC
:Imports: :doc:`base/frameworks/notice/weird.zeek </scripts/base/frameworks/notice/weird.zeek>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/quic/consts.zeek </scripts/base/protocols/quic/consts.zeek>`

Summary
~~~~~~~
Types
#####
============================================ =
:zeek:type:`QUIC::Info`: :zeek:type:`record` 
============================================ =

Redefinitions
#############
============================================ ======================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      
                                             
                                             * :zeek:enum:`QUIC::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               quic: :zeek:type:`QUIC::Info` :zeek:attr:`&optional`
============================================ ======================================================

Events
######
============================================= =
:zeek:id:`QUIC::log_quic`: :zeek:type:`event` 
============================================= =

Hooks
#####
============================================================== =
:zeek:id:`QUIC::finalize_quic`: :zeek:type:`Conn::RemovalHook` 
:zeek:id:`QUIC::log_policy`: :zeek:type:`Log::PolicyHook`      
============================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: QUIC::Info
   :source-code: base/protocols/quic/main.zeek 13 65

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp of first QUIC packet for this entry.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      version: :zeek:type:`string` :zeek:attr:`&log`
         QUIC version as found in the first INITIAL packet from
         the client.

      client_initial_dcid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         First Destination Connection ID used by client. This is
         random and unpredictable, but used for packet protection
         by client and server.

      server_scid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Server chosen Connection ID usually from server's first
         INITIAL packet. This is to be used by the client in
         subsequent packets.

      server_name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Server name extracted from SNI extension in ClientHello
         packet if available.

      client_protocol: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         First protocol extracted from ALPN extension in ClientHello
         packet if available.

      history: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         Experimental QUIC history.
         
         Letters have the following meaning with client-sent
         letters being capitalized:
         
         ======  ====================================================
         Letter  Meaning
         ======  ====================================================
         I       INIT packet
         H       HANDSHAKE packet
         Z       0RTT packet
         R       RETRY packet
         C       CONNECTION_CLOSE packet
         S       SSL Client/Server Hello
         ======  ====================================================

      history_state: :zeek:type:`vector` of :zeek:type:`string`

      logged: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`


Events
######
.. zeek:id:: QUIC::log_quic
   :source-code: base/protocols/quic/main.zeek 67 67

   :Type: :zeek:type:`event` (rec: :zeek:type:`QUIC::Info`)


Hooks
#####
.. zeek:id:: QUIC::finalize_quic
   :source-code: base/protocols/quic/main.zeek 203 209

   :Type: :zeek:type:`Conn::RemovalHook`


.. zeek:id:: QUIC::log_policy
   :source-code: base/protocols/quic/main.zeek 69 69

   :Type: :zeek:type:`Log::PolicyHook`


