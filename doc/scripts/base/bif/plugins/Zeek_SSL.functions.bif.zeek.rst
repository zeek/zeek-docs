:tocdepth: 3

base/bif/plugins/Zeek_SSL.functions.bif.zeek
============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Functions
#########
===================================================== ==============================================================================
:zeek:id:`set_keys`: :zeek:type:`function`            Set the decryption keys that should be used to decrypt
                                                      TLS application data in the connection.
:zeek:id:`set_secret`: :zeek:type:`function`          Set the secret that should be used to derive keys for the connection.
:zeek:id:`set_ssl_established`: :zeek:type:`function` Sets if the SSL analyzer should consider the connection established (handshake
                                                      finished successfully).
===================================================== ==============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: set_keys
   :source-code: base/bif/plugins/Zeek_SSL.functions.bif.zeek 35 35

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, keys: :zeek:type:`string`) : :zeek:type:`bool`

   Set the decryption keys that should be used to decrypt
   TLS application data in the connection.
   

   :c: The affected connection
   

   :keys: The key buffer as derived via TLS PRF.
   

   :returns: T on success, F on failure.

.. zeek:id:: set_secret
   :source-code: base/bif/plugins/Zeek_SSL.functions.bif.zeek 24 24

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, secret: :zeek:type:`string`) : :zeek:type:`bool`

   Set the secret that should be used to derive keys for the connection.
   (For TLS 1.2 this is the pre-master secret).
   

   :c: The affected connection
   

   :secret: secret to set
   

   :returns: T on success, F on failure.

.. zeek:id:: set_ssl_established
   :source-code: base/bif/plugins/Zeek_SSL.functions.bif.zeek 13 13

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`) : :zeek:type:`bool`

   Sets if the SSL analyzer should consider the connection established (handshake
   finished successfully).
   

   :c: The SSL connection.
   

   :returns: T on success, F on failure.


