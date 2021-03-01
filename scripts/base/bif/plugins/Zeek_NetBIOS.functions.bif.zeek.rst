:tocdepth: 3

base/bif/plugins/Zeek_NetBIOS.functions.bif.zeek
================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================== ================================================================
:zeek:id:`decode_netbios_name`: :zeek:type:`function`      Decode a NetBIOS name.
:zeek:id:`decode_netbios_name_type`: :zeek:type:`function` Converts a NetBIOS name type to its corresponding numeric value.
========================================================== ================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: decode_netbios_name
   :source-code: base/bif/plugins/Zeek_NetBIOS.functions.bif.zeek 13 13

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Decode a NetBIOS name.  See https://jeffpar.github.io/kbarchive/kb/194/Q194203/.
   

   :name: The encoded NetBIOS name, e.g., ``"FEEIEFCAEOEFFEECEJEPFDCAEOEBENEF"``.
   

   :returns: The decoded NetBIOS name, e.g., ``"THE NETBIOS NAME"``.
   
   .. zeek:see:: decode_netbios_name_type

.. zeek:id:: decode_netbios_name_type
   :source-code: base/bif/plugins/Zeek_NetBIOS.functions.bif.zeek 24 24

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`count`

   Converts a NetBIOS name type to its corresponding numeric value.
   See https://en.wikipedia.org/wiki/NetBIOS#NetBIOS_Suffixes.
   

   :name: The NetBIOS name type.
   

   :returns: The numeric value of *name*.
   
   .. zeek:see:: decode_netbios_name


