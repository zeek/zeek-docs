:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_transaction2.bif.bro
======================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================================= ===========================================================================================
:bro:id:`smb1_trans2_find_first2_request`: :bro:type:`event`      Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                  version 1 *transaction2* requests of subtype *find first2*.
:bro:id:`smb1_trans2_get_dfs_referral_request`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                  version 1 *transaction2* requests of subtype *get DFS referral*.
:bro:id:`smb1_trans2_query_path_info_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                  version 1 *transaction2* requests of subtype *query path info*.
:bro:id:`smb1_transaction2_request`: :bro:type:`event`            Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                                  version 1 requests of type *transaction2*.
================================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_trans2_find_first2_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, args: :bro:type:`SMB1::Find_First2_Request_Args`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *find first2*. This transaction is used to begin
   a search for file(s) within a directory or for a directory
   
   For more information, see MS-CIFS:2.2.6.2
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :args: A record data structure with arguments given to the command.
   
   .. bro:see:: smb1_message smb1_transaction2_request smb1_trans2_query_path_info_request
      smb1_trans2_get_dfs_referral_request

.. bro:id:: smb1_trans2_get_dfs_referral_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_name: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *get DFS referral*. This transaction is used
   to request a referral for a disk object in DFS.
   
   For more information, see MS-CIFS:2.2.6.16
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :file_name: File name the request is in reference to.
   
   .. bro:see:: smb1_message smb1_transaction2_request smb1_trans2_find_first2_request
      smb1_trans2_query_path_info_request

.. bro:id:: smb1_trans2_query_path_info_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_name: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *query path info*. This transaction is used to
   get information about a specific file or directory.
   
   For more information, see MS-CIFS:2.2.6.6
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :file_name: File name the request is in reference to. 
   
   .. bro:see:: smb1_message smb1_transaction2_request smb1_trans2_find_first2_request
      smb1_trans2_get_dfs_referral_request

.. bro:id:: smb1_transaction2_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, args: :bro:type:`SMB1::Trans2_Args`, sub_cmd: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction2*. This command serves as the transport for the
   Transaction2 Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system. Compared to the
   Transaction Subprotocol Commands, these commands allow clients to set and retrieve Extended
   Attribute key/value pairs, make use of long file names (longer than the original 8.3 format
   names), and perform directory searches, among other tasks.
   
   For more information, see MS-CIFS:2.2.4.46
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :sub_cmd: The sub command, some are parsed and have their own events.
   
   .. bro:see:: smb1_message smb1_trans2_find_first2_request smb1_trans2_query_path_info_request
      smb1_trans2_get_dfs_referral_request smb1_transaction_request


