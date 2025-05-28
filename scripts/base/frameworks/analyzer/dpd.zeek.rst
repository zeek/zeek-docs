:tocdepth: 3

base/frameworks/analyzer/dpd.zeek
=================================
.. zeek:namespace:: DPD

Activates port-independent protocol detection and selectively disables
analyzers if protocol violations occur.

:Namespace: DPD

Summary
~~~~~~~
Runtime Options
###############
============================================================================================================================================================ =========================================================================
:zeek:id:`DPD::ignore_violations`: :zeek:type:`set` :zeek:attr:`&redef`                                                                                      Analyzers which you don't want to throw
:zeek:id:`DPD::ignore_violations_after`: :zeek:type:`count` :zeek:attr:`&redef`                                                                              Ignore violations which go this many bytes into the connection.
:zeek:id:`DPD::max_violations`: :zeek:type:`table` :zeek:attr:`&deprecated` = *...* :zeek:attr:`&default` = ``5`` :zeek:attr:`&optional` :zeek:attr:`&redef` Deprecated, please see https://github.com/zeek/zeek/pull/4200 for details
:zeek:id:`DPD::track_removed_services_in_connection`: :zeek:type:`bool` :zeek:attr:`&redef`                                                                  Change behavior of service field in conn.log:
                                                                                                                                                             Failed services are no longer removed.
============================================================================================================================================================ =========================================================================

Types
#####
=========================================== ======================================================================
:zeek:type:`DPD::Info`: :zeek:type:`record` The record type defining the columns to log in the DPD logging stream.
=========================================== ======================================================================

Redefinitions
#############
============================================ ===================================================================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      Add the DPD logging stream identifier.
                                             
                                             * :zeek:enum:`DPD::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               dpd: :zeek:type:`DPD::Info` :zeek:attr:`&optional`
                                             
                                               service_violation: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
                                                 The set of services (analyzers) for which Zeek has observed a
                                                 violation after the same service had previously been confirmed.
============================================ ===================================================================================================================

Hooks
#####
======================================================== =============================================
:zeek:id:`DPD::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
======================================================== =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: DPD::ignore_violations
   :source-code: base/frameworks/analyzer/dpd.zeek 33 33

   :Type: :zeek:type:`set` [:zeek:type:`Analyzer::Tag`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/protocols/dce-rpc/main.zeek`

      ``+=``::

         Analyzer::ANALYZER_DCE_RPC

   :Redefinition: from :doc:`/scripts/base/protocols/ntlm/main.zeek`

      ``+=``::

         Analyzer::ANALYZER_NTLM


   Analyzers which you don't want to throw

.. zeek:id:: DPD::ignore_violations_after
   :source-code: base/frameworks/analyzer/dpd.zeek 37 37

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10240``

   Ignore violations which go this many bytes into the connection.
   Set to 0 to never ignore protocol violations.

.. zeek:id:: DPD::max_violations
   :source-code: base/frameworks/analyzer/dpd.zeek 30 30

   :Type: :zeek:type:`table` [:zeek:type:`Analyzer::Tag`] of :zeek:type:`count`
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v8.1: This has become non-functional in Zeek 7.2, see PR #4200"* :zeek:attr:`&default` = ``5`` :zeek:attr:`&optional` :zeek:attr:`&redef`
   :Default: ``{}``

   Deprecated, please see https://github.com/zeek/zeek/pull/4200 for details

.. zeek:id:: DPD::track_removed_services_in_connection
   :source-code: base/frameworks/analyzer/dpd.zeek 44 44

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Change behavior of service field in conn.log:
   Failed services are no longer removed. Instead, for a failed
   service, a second entry with a "-" in front of it is added.
   E.g. a http connection with a violation would be logged as
   "http,-http".

Types
#####
.. zeek:type:: DPD::Info
   :source-code: base/frameworks/analyzer/dpd.zeek 14 27

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when protocol analysis failed.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Connection unique ID.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      Connection ID containing the 4-tuple which identifies endpoints.


   .. zeek:field:: proto :zeek:type:`transport_proto` :zeek:attr:`&log`

      Transport protocol for the violation.


   .. zeek:field:: analyzer :zeek:type:`string` :zeek:attr:`&log`

      The analyzer that generated the violation.


   .. zeek:field:: failure_reason :zeek:type:`string` :zeek:attr:`&log`

      The textual reason for the analysis failure.


   .. zeek:field:: packet_segment :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/policy/frameworks/dpd/packet-segment-logging.zeek` is loaded)

      A chunk of the payload that most likely resulted in the
      analyzer violation.


   The record type defining the columns to log in the DPD logging stream.

Hooks
#####
.. zeek:id:: DPD::log_policy
   :source-code: base/frameworks/analyzer/dpd.zeek 11 11

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


