:tocdepth: 3

base/protocols/quic/consts.zeek
===============================
.. zeek:namespace:: QUIC


:Namespace: QUIC

Summary
~~~~~~~
Constants
#########
================================================================================================== =
:zeek:id:`QUIC::version_strings`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` 
================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: QUIC::version_strings
   :source-code: base/protocols/quic/consts.zeek 4 4

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [1] = "1"
         }




