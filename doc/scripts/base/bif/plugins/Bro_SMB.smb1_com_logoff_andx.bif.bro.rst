:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_logoff_andx.bif.bro
=====================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================= ===========================================================================================
:bro:id:`smb1_logoff_andx`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                              version 1 requests of type *logoff andx*.
============================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_logoff_andx

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *logoff andx*. This is used by the client to logoff the user
   connection represented by UID in the SMB Header. The server releases all locks and closes
   all files currently open by this user, disconnects all tree connects, cancels any outstanding
   requests for this UID, and invalidates the UID.
   
   For more information, see MS-CIFS:2.2.4.54
   

   :c: The connection.
   

   :is_orig: Indicates which host sent the logoff message.
   
   .. bro:see:: smb1_message


