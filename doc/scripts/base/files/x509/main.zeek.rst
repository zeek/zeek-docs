:tocdepth: 3

base/files/x509/main.zeek
=========================
.. zeek:namespace:: X509


:Namespace: X509
:Imports: :doc:`base/files/hash </scripts/base/files/hash/index>`, :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================================= =====================================================================
:zeek:id:`X509::caching_required_encounters`: :zeek:type:`count` :zeek:attr:`&redef`                    How often do you have to encounter a certificate before
                                                                                                        caching it.
:zeek:id:`X509::caching_required_encounters_interval`: :zeek:type:`interval` :zeek:attr:`&redef`        The timespan over which caching_required_encounters has to be reached
:zeek:id:`X509::certificate_cache_max_entries`: :zeek:type:`count` :zeek:attr:`&redef`                  Maximum size of the certificate cache
:zeek:id:`X509::certificate_cache_minimum_eviction_interval`: :zeek:type:`interval` :zeek:attr:`&redef` After a certificate has not been encountered for this time, it
                                                                                                        may be evicted from the certificate cache.
======================================================================================================= =====================================================================

Types
#####
=============================================== ================================================================
:zeek:type:`X509::Info`: :zeek:type:`record`    The record type which contains the fields of the X.509 log.
:zeek:type:`X509::SctInfo`: :zeek:type:`record` This record is used to store information about the SCTs that are
                                                encountered in Certificates.
=============================================== ================================================================

Redefinitions
#############
================================================================= =
:zeek:type:`Files::Info`: :zeek:type:`record` :zeek:attr:`&redef` 
:zeek:type:`Log::ID`: :zeek:type:`enum`                           
================================================================= =

Events
######
============================================= ===================================
:zeek:id:`X509::log_x509`: :zeek:type:`event` Event for accessing logged records.
============================================= ===================================

Hooks
#####
================================================================= ===================================================================
:zeek:id:`X509::log_policy`: :zeek:type:`Log::PolicyHook`         
:zeek:id:`X509::x509_certificate_cache_replay`: :zeek:type:`hook` This hook performs event-replays in case a certificate that already
                                                                  is in the cache is encountered.
================================================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: X509::caching_required_encounters

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10``

   How often do you have to encounter a certificate before
   caching it. Set to 0 to disable caching of certificates.

.. zeek:id:: X509::caching_required_encounters_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min 2.0 secs``

   The timespan over which caching_required_encounters has to be reached

.. zeek:id:: X509::certificate_cache_max_entries

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10000``

   Maximum size of the certificate cache

.. zeek:id:: X509::certificate_cache_minimum_eviction_interval

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min 2.0 secs``

   After a certificate has not been encountered for this time, it
   may be evicted from the certificate cache.

Types
#####
.. zeek:type:: X509::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Current timestamp.

      id: :zeek:type:`string` :zeek:attr:`&log`
         File id of this certificate.

      certificate: :zeek:type:`X509::Certificate` :zeek:attr:`&log`
         Basic information about the certificate.

      handle: :zeek:type:`opaque` of x509
         The opaque wrapping the certificate. Mainly used
         for the verify operations.

      extensions: :zeek:type:`vector` of :zeek:type:`X509::Extension` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         All extensions that were encountered in the certificate.

      san: :zeek:type:`X509::SubjectAlternativeName` :zeek:attr:`&optional` :zeek:attr:`&log`
         Subject alternative name extension of the certificate.

      basic_constraints: :zeek:type:`X509::BasicConstraints` :zeek:attr:`&optional` :zeek:attr:`&log`
         Basic constraints extension of the certificate.

      extensions_cache: :zeek:type:`vector` of :zeek:type:`any` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         All extensions in the order they were raised.
         This is used for caching certificates that are commonly
         encountered and should not be relied on in user scripts.

      logcert: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/ssl/log-hostcerts-only.zeek` is loaded)

         Logging of certificate is suppressed if set to F

   The record type which contains the fields of the X.509 log.

.. zeek:type:: X509::SctInfo

   :Type: :zeek:type:`record`

      version: :zeek:type:`count`
         The version of the encountered SCT (should always be 0 for v1).

      logid: :zeek:type:`string`
         The ID of the log issuing this SCT.

      timestamp: :zeek:type:`count`
         The timestamp at which this SCT was issued measured since the
         epoch (January 1, 1970, 00:00), ignoring leap seconds, in
         milliseconds. Not converted to a Zeek timestamp because we need
         the exact value for validation.

      hash_alg: :zeek:type:`count`
         The hash algorithm used for this sct.

      sig_alg: :zeek:type:`count`
         The signature algorithm used for this sct.

      signature: :zeek:type:`string`
         The signature of this SCT.

   This record is used to store information about the SCTs that are
   encountered in Certificates.

Events
######
.. zeek:id:: X509::log_x509

   :Type: :zeek:type:`event` (rec: :zeek:type:`X509::Info`)

   Event for accessing logged records.

Hooks
#####
.. zeek:id:: X509::log_policy

   :Type: :zeek:type:`Log::PolicyHook`


.. zeek:id:: X509::x509_certificate_cache_replay

   :Type: :zeek:type:`hook` (f: :zeek:type:`fa_file`, e: :zeek:type:`X509::Info`, sha256: :zeek:type:`string`) : :zeek:type:`bool`

   This hook performs event-replays in case a certificate that already
   is in the cache is encountered.
   
   It is possible to change this behavior/skip sending the events by
   installing a higher priority hook instead.


