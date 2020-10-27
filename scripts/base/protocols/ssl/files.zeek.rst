:tocdepth: 3

base/protocols/ssl/files.zeek
=============================
.. zeek:namespace:: SSL


:Namespace: SSL
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/ssl/main.zeek </scripts/base/protocols/ssl/main.zeek>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== ==============================================================================================================
:zeek:type:`SSL::Info`: :zeek:type:`record` 
                                            
                                            :New Fields: :zeek:type:`SSL::Info`
                                            
                                              cert_chain: :zeek:type:`vector` of :zeek:type:`Files::Info` :zeek:attr:`&optional`
                                                Chain of certificates offered by the server to validate its
                                                complete signing chain.
                                            
                                              cert_chain_fuids: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                An ordered vector of all certificate file unique IDs for the
                                                certificates offered by the server.
                                            
                                              client_cert_chain: :zeek:type:`vector` of :zeek:type:`Files::Info` :zeek:attr:`&optional`
                                                Chain of certificates offered by the client to validate its
                                                complete signing chain.
                                            
                                              client_cert_chain_fuids: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                An ordered vector of all certificate file unique IDs for the
                                                certificates offered by the client.
                                            
                                              subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Subject of the X.509 certificate offered by the server.
                                            
                                              issuer: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Subject of the signer of the X.509 certificate offered by the
                                                server.
                                            
                                              client_subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Subject of the X.509 certificate offered by the client.
                                            
                                              client_issuer: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                Subject of the signer of the X.509 certificate offered by the
                                                client.
                                            
                                              server_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                Current number of certificates seen from either side.
                                            
                                              client_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
=========================================== ==============================================================================================================

Functions
#########
====================================================== =====================================
:zeek:id:`SSL::describe_file`: :zeek:type:`function`   Default file describer for SSL.
:zeek:id:`SSL::get_file_handle`: :zeek:type:`function` Default file handle provider for SSL.
====================================================== =====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: SSL::describe_file

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`) : :zeek:type:`string`

   Default file describer for SSL.

.. zeek:id:: SSL::get_file_handle

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`string`

   Default file handle provider for SSL.


