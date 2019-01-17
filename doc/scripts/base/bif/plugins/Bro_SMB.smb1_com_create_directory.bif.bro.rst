:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_create_directory.bif.bro
==========================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================================== ===========================================================================================
:bro:id:`smb1_create_directory_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                            version 1 requests of type *create directory*.
:bro:id:`smb1_create_directory_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                            version 1 responses of type *create directory*.
=========================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_create_directory_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, directory_name: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *create directory*. This is a deprecated command which
   has been replaced by the *trans2_create_directory* subcommand. This is used by the client to
   create a new directory on the server, relative to a connected share.
   
   For more information, see MS-CIFS:2.2.4.1
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :directory_name: The name of the directory to create.
   
   .. bro:see:: smb1_message smb1_create_directory_response smb1_transaction2_request

.. bro:id:: smb1_create_directory_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *create directory*. This is a deprecated command which
   has been replaced by the *trans2_create_directory* subcommand. This is the server response
   to the *create directory* request.
   
   For more information, see MS-CIFS:2.2.4.1
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   
   .. bro:see:: smb1_message smb1_create_directory_request smb1_transaction2_request


