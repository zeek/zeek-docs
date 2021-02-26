:tocdepth: 3

policy/integration/barnyard2/main.zeek
======================================
.. zeek:namespace:: Barnyard2

This script lets Barnyard2 integrate with Zeek.  It receives alerts from
Barnyard2 and logs them.  In the future it will do more correlation
and derive new notices from the alerts.

:Namespace: Barnyard2
:Imports: :doc:`policy/integration/barnyard2/types.zeek </scripts/policy/integration/barnyard2/types.zeek>`

Summary
~~~~~~~
Types
#####
================================================= =
:zeek:type:`Barnyard2::Info`: :zeek:type:`record` 
================================================= =

Redefinitions
#############
======================================= =============================
:zeek:type:`Log::ID`: :zeek:type:`enum` 
                                        
                                        * :zeek:enum:`Barnyard2::LOG`
======================================= =============================

Hooks
#####
============================================================== =
:zeek:id:`Barnyard2::log_policy`: :zeek:type:`Log::PolicyHook` 
============================================================== =

Functions
#########
==================================================== ======================================================================
:zeek:id:`Barnyard2::pid2cid`: :zeek:type:`function` This can convert a Barnyard :zeek:type:`Barnyard2::PacketID` value to
                                                     a :zeek:type:`conn_id` value in the case that you might need to index 
                                                     into an existing data structure elsewhere within Zeek.
==================================================== ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Barnyard2::Info
   :source-code: policy/integration/barnyard2/main.zeek 14 21

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp of the alert.

      pid: :zeek:type:`Barnyard2::PacketID` :zeek:attr:`&log`
         Associated packet ID.

      alert: :zeek:type:`Barnyard2::AlertData` :zeek:attr:`&log`
         Associated alert data.


Hooks
#####
.. zeek:id:: Barnyard2::log_policy
   :source-code: policy/integration/barnyard2/main.zeek 12 12

   :Type: :zeek:type:`Log::PolicyHook`


Functions
#########
.. zeek:id:: Barnyard2::pid2cid
   :source-code: policy/integration/barnyard2/main.zeek 35 38

   :Type: :zeek:type:`function` (p: :zeek:type:`Barnyard2::PacketID`) : :zeek:type:`conn_id`

   This can convert a Barnyard :zeek:type:`Barnyard2::PacketID` value to
   a :zeek:type:`conn_id` value in the case that you might need to index 
   into an existing data structure elsewhere within Zeek.


