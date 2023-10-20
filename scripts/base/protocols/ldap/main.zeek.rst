:tocdepth: 3

base/protocols/ldap/main.zeek
=============================
.. zeek:namespace:: LDAP


:Namespace: LDAP
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/ldap/consts.zeek </scripts/base/protocols/ldap/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
===================================================================================== =================================================
:zeek:id:`LDAP::default_capture_password`: :zeek:type:`bool` :zeek:attr:`&redef`      Whether clear text passwords are captured or not.
:zeek:id:`LDAP::default_log_search_attributes`: :zeek:type:`bool` :zeek:attr:`&redef` Whether to log LDAP search attributes or not.
===================================================================================== =================================================

Redefinable Options
###################
================================================================ ==================================================
:zeek:id:`LDAP::ports_tcp`: :zeek:type:`set` :zeek:attr:`&redef` TCP ports which should be considered for analysis.
:zeek:id:`LDAP::ports_udp`: :zeek:type:`set` :zeek:attr:`&redef` UDP ports which should be considered for analysis.
================================================================ ==================================================

Types
#####
=================================================== =
:zeek:type:`LDAP::MessageInfo`: :zeek:type:`record` 
:zeek:type:`LDAP::SearchInfo`: :zeek:type:`record`  
:zeek:type:`LDAP::State`: :zeek:type:`record`       
=================================================== =

Redefinitions
#############
==================================================================== =======================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
                                                                     
                                                                     * :zeek:enum:`LDAP::LDAP_LOG`
                                                                     
                                                                     * :zeek:enum:`LDAP::LDAP_SEARCH_LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       ldap: :zeek:type:`LDAP::State` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =======================================================

Events
######
==================================================== =
:zeek:id:`LDAP::log_ldap`: :zeek:type:`event`        
:zeek:id:`LDAP::log_ldap_search`: :zeek:type:`event` 
==================================================== =

Hooks
#####
================================================================ ================================================
:zeek:id:`LDAP::finalize_ldap`: :zeek:type:`Conn::RemovalHook`   LDAP finalization hook.
:zeek:id:`LDAP::log_policy`: :zeek:type:`Log::PolicyHook`        Default logging policy hook for LDAP_LOG.
:zeek:id:`LDAP::log_policy_search`: :zeek:type:`Log::PolicyHook` Default logging policy hook for LDAP_SEARCH_LOG.
================================================================ ================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: LDAP::default_capture_password
   :source-code: base/protocols/ldap/main.zeek 19 19

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Whether clear text passwords are captured or not.

.. zeek:id:: LDAP::default_log_search_attributes
   :source-code: base/protocols/ldap/main.zeek 22 22

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Whether to log LDAP search attributes or not.

Redefinable Options
###################
.. zeek:id:: LDAP::ports_tcp
   :source-code: base/protocols/ldap/main.zeek 13 13

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            3268/tcp,
            389/tcp
         }


   TCP ports which should be considered for analysis.

.. zeek:id:: LDAP::ports_udp
   :source-code: base/protocols/ldap/main.zeek 16 16

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            389/udp
         }


   UDP ports which should be considered for analysis.

Types
#####
.. zeek:type:: LDAP::MessageInfo
   :source-code: base/protocols/ldap/main.zeek 36 66

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`

      uid: :zeek:type:`string` :zeek:attr:`&log`

      id: :zeek:type:`conn_id` :zeek:attr:`&log`

      message_id: :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`

      version: :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`

      opcodes: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`

      results: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`

      diagnostic_messages: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      objects: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      arguments: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`


.. zeek:type:: LDAP::SearchInfo
   :source-code: base/protocols/ldap/main.zeek 71 105

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`

      uid: :zeek:type:`string` :zeek:attr:`&log`

      id: :zeek:type:`conn_id` :zeek:attr:`&log`

      message_id: :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`

      scopes: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`

      derefs: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`

      base_objects: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      result_count: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      results: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`

      diagnostic_messages: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      filter: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      attributes: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`


.. zeek:type:: LDAP::State
   :source-code: base/protocols/ldap/main.zeek 107 110

   :Type: :zeek:type:`record`

      messages: :zeek:type:`table` [:zeek:type:`int`] of :zeek:type:`LDAP::MessageInfo` :zeek:attr:`&optional`

      searches: :zeek:type:`table` [:zeek:type:`int`] of :zeek:type:`LDAP::SearchInfo` :zeek:attr:`&optional`


Events
######
.. zeek:id:: LDAP::log_ldap
   :source-code: base/protocols/ldap/main.zeek 114 114

   :Type: :zeek:type:`event` (rec: :zeek:type:`LDAP::MessageInfo`)


.. zeek:id:: LDAP::log_ldap_search
   :source-code: base/protocols/ldap/main.zeek 115 115

   :Type: :zeek:type:`event` (rec: :zeek:type:`LDAP::SearchInfo`)


Hooks
#####
.. zeek:id:: LDAP::finalize_ldap
   :source-code: base/protocols/ldap/main.zeek 331 357

   :Type: :zeek:type:`Conn::RemovalHook`

   LDAP finalization hook.

.. zeek:id:: LDAP::log_policy
   :source-code: base/protocols/ldap/main.zeek 25 25

   :Type: :zeek:type:`Log::PolicyHook`

   Default logging policy hook for LDAP_LOG.

.. zeek:id:: LDAP::log_policy_search
   :source-code: base/protocols/ldap/main.zeek 28 28

   :Type: :zeek:type:`Log::PolicyHook`

   Default logging policy hook for LDAP_SEARCH_LOG.


