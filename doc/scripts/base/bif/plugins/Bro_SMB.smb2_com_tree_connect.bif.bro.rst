:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_com_tree_connect.bif.bro
======================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================= ===========================================================================================
:bro:id:`smb2_tree_connect_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                        version 2 requests of type *tree_connect*.
:bro:id:`smb2_tree_connect_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                        version 2 responses of type *tree_connect*.
======================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb2_tree_connect_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, path: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree_connect*. This is sent by a client to request access to a
   particular share on the server.
   
   For more information, see MS-SMB2:2.2.9
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :path: Path of the requested tree.
   
   .. bro:see:: smb2_message smb2_tree_connect_response

.. bro:id:: smb2_tree_connect_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, response: :bro:type:`SMB2::TreeConnectResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *tree_connect*. This is sent by the server when a *tree_connect*
   request is successfully processed by the server.
   
   For more information, see MS-SMB2:2.2.10
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :response: A record with more information related to the response.
   
   .. bro:see:: smb2_message smb2_tree_connect_request


