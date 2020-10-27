:tocdepth: 3

base/protocols/smb/smb2-main.zeek
=================================
.. zeek:namespace:: SMB2


:Namespace: SMB2
:Imports: :doc:`base/protocols/smb/main.zeek </scripts/base/protocols/smb/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================== ======================================================================
:zeek:type:`SMB::CmdInfo`: :zeek:type:`record` 
                                               
                                               :New Fields: :zeek:type:`SMB::CmdInfo`
                                               
                                                 smb2_offered_dialects: :zeek:type:`index_vec` :zeek:attr:`&optional`
                                                   Dialects offered by the client.
============================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

