:tocdepth: 3

policy/protocols/conn/protocol-strings.zeek
===========================================
.. zeek:namespace:: Conn

This script adds a string version of the protocol_id field

:Namespace: Conn
:Imports: :doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ =============================================================================
:zeek:type:`Conn::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`Conn::Info`
                                             
                                               protocol_name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 A string version of the protocol_id field
============================================ =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

