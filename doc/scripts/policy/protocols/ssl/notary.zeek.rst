:tocdepth: 3

policy/protocols/ssl/notary.zeek
================================
.. zeek:namespace:: CertNotary


:Namespace: CertNotary
:Imports: :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Runtime Options
###############
====================================================================== ===========================
:zeek:id:`CertNotary::domain`: :zeek:type:`string` :zeek:attr:`&redef` The notary domain to query.
====================================================================== ===========================

Types
#####
====================================================== ============================================
:zeek:type:`CertNotary::Response`: :zeek:type:`record` A response from the ICSI certificate notary.
====================================================== ============================================

Redefinitions
#############
=========================================== ====================================================================================
:zeek:type:`SSL::Info`: :zeek:type:`record` 
                                            
                                            :New Fields: :zeek:type:`SSL::Info`
                                            
                                              notary: :zeek:type:`CertNotary::Response` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                A response from the ICSI certificate notary.
=========================================== ====================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: CertNotary::domain
   :source-code: policy/protocols/ssl/notary.zeek 17 17

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"notary.icsi.berkeley.edu"``

   The notary domain to query.

Types
#####
.. zeek:type:: CertNotary::Response
   :source-code: policy/protocols/ssl/notary.zeek 9 14

   :Type: :zeek:type:`record`

      first_seen: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      last_seen: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      times_seen: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      valid: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

   A response from the ICSI certificate notary.


