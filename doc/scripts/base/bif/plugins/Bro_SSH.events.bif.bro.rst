:tocdepth: 3

base/bif/plugins/Bro_SSH.events.bif.bro
=======================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================== ==================================================================
:bro:id:`ssh1_server_host_key`: :bro:type:`event`  During the :abbr:`SSH (Secure Shell)` key exchange, the server
                                                   supplies its public host key.
:bro:id:`ssh2_dh_server_params`: :bro:type:`event` Generated if the connection uses a Diffie-Hellman Group Exchange
                                                   key exchange method.
:bro:id:`ssh2_ecc_key`: :bro:type:`event`          The :abbr:`ECDH (Elliptic Curve Diffie-Hellman)` and
                                                   :abbr:`ECMQV (Elliptic Curve Menezes-Qu-Vanstone)` key exchange
                                                   algorithms use two ephemeral key pairs to generate a shared
                                                   secret.
:bro:id:`ssh2_gss_error`: :bro:type:`event`        In the event of a GSS-API error on the server, the server MAY send
                                                   send an error message with some additional details.
:bro:id:`ssh2_server_host_key`: :bro:type:`event`  During the :abbr:`SSH (Secure Shell)` key exchange, the server
                                                   supplies its public host key.
:bro:id:`ssh_auth_attempted`: :bro:type:`event`    This event is generated when an :abbr:`SSH (Secure Shell)`
                                                   connection was determined to have had an authentication attempt.
:bro:id:`ssh_auth_successful`: :bro:type:`event`   This event is generated when an :abbr:`SSH (Secure Shell)`
                                                   connection was determined to have had a successful
                                                   authentication.
:bro:id:`ssh_capabilities`: :bro:type:`event`      During the initial :abbr:`SSH (Secure Shell)` key exchange, each
                                                   endpoint lists the algorithms that it supports, in order of
                                                   preference.
:bro:id:`ssh_client_version`: :bro:type:`event`    An :abbr:`SSH (Secure Shell)` Protocol Version Exchange message
                                                   from the client.
:bro:id:`ssh_encrypted_packet`: :bro:type:`event`  This event is generated when an :abbr:`SSH (Secure Shell)`
                                                   encrypted packet is seen.
:bro:id:`ssh_server_version`: :bro:type:`event`    An :abbr:`SSH (Secure Shell)` Protocol Version Exchange message
                                                   from the server.
================================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: ssh1_server_host_key

   :Type: :bro:type:`event` (c: :bro:type:`connection`, p: :bro:type:`string`, e: :bro:type:`string`)

   During the :abbr:`SSH (Secure Shell)` key exchange, the server
   supplies its public host key. This event is generated when the
   appropriate key exchange message is seen for SSH1.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :p: The prime for the server's public host key.
   

   :e: The exponent for the serer's public host key.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh2_dh_server_params

   :Type: :bro:type:`event` (c: :bro:type:`connection`, p: :bro:type:`string`, q: :bro:type:`string`)

   Generated if the connection uses a Diffie-Hellman Group Exchange
   key exchange method. This event contains the server DH parameters,
   which are sent in the SSH_MSG_KEY_DH_GEX_GROUP message as defined in
   :rfc:`4419#section-3`.
   

   :c: The connection.
   

   :p: The DH prime modulus.
   

   :q: The DH generator.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh1_server_host_key ssh_server_host_key ssh_encrypted_packet
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh2_ecc_key

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, q: :bro:type:`string`)

   The :abbr:`ECDH (Elliptic Curve Diffie-Hellman)` and
   :abbr:`ECMQV (Elliptic Curve Menezes-Qu-Vanstone)` key exchange
   algorithms use two ephemeral key pairs to generate a shared
   secret. This event is generated when either the client's or
   server's ephemeral public key is seen. For more information, see:
   :rfc:`5656#section-4`.
   

   :c: The connection
   

   :is_orig: Did this message come from the originator?
   

   :q: The ephemeral public key
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh1_server_host_key ssh_server_host_key ssh_encrypted_packet
      ssh2_dh_server_params ssh2_gss_error

.. bro:id:: ssh2_gss_error

   :Type: :bro:type:`event` (c: :bro:type:`connection`, major_status: :bro:type:`count`, minor_status: :bro:type:`count`, err_msg: :bro:type:`string`)

   In the event of a GSS-API error on the server, the server MAY send
   send an error message with some additional details. This event is
   generated when such an error message is seen. For more information,
   see :rfc:`4462#section-2.1`.
   

   :c: The connection.
   

   :major_status: GSS-API major status code.
   

   :minor_status: GSS-API minor status code.
   

   :err_msg: Detailed human-readable error message
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh1_server_host_key ssh_server_host_key ssh_encrypted_packet
      ssh2_dh_server_params ssh2_ecc_key

.. bro:id:: ssh2_server_host_key

   :Type: :bro:type:`event` (c: :bro:type:`connection`, key: :bro:type:`string`)

   During the :abbr:`SSH (Secure Shell)` key exchange, the server
   supplies its public host key. This event is generated when the
   appropriate key exchange message is seen for SSH2.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :key: The server's public host key. Note that this is the public key
      itself, and not just the fingerprint or hash.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh_auth_attempted

   :Type: :bro:type:`event` (c: :bro:type:`connection`, authenticated: :bro:type:`bool`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   connection was determined to have had an authentication attempt.
   This determination is based on packet size analysis, and errs
   on the side of caution - that is, if there's any doubt about
   whether or not an authenication attempt occured, this event is
   *not* raised.
   
   At this point in the protocol, all we can determine is whether
   or not the user is authenticated. We don't know if the particular
   attempt succeeded or failed, since some servers require multiple
   authentications (e.g. require both a password AND a pubkey), and
   could return an authentication failed message which is marked
   as a partial success.
   
   This event will often be raised multiple times per connection.
   In almost all connections, it will be raised once unless
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :authenticated: This is true if the analyzer detected a
      successful connection from the authentication attempt.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh_auth_successful

   :Type: :bro:type:`event` (c: :bro:type:`connection`, auth_method_none: :bro:type:`bool`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   connection was determined to have had a successful
   authentication. This determination is based on packet size
   analysis, and errs on the side of caution - that is, if there's any
   doubt about the authentication success, this event is *not* raised.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :auth_method_none: This is true if the analyzer detected a
      successful connection before any authentication challenge. The
      :abbr:`SSH (Secure Shell)` protocol provides a mechanism for
      unauthenticated access, which some servers support.
   
   .. bro:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_attempted ssh_capabilities
      ssh2_server_host_key ssh1_server_host_key ssh_server_host_key
      ssh_encrypted_packet ssh2_dh_server_params ssh2_gss_error
      ssh2_ecc_key

.. bro:id:: ssh_capabilities

   :Type: :bro:type:`event` (c: :bro:type:`connection`, cookie: :bro:type:`string`, capabilities: :bro:type:`SSH::Capabilities`)

   During the initial :abbr:`SSH (Secure Shell)` key exchange, each
   endpoint lists the algorithms that it supports, in order of
   preference. This event is generated for each endpoint, when the
   SSH_MSG_KEXINIT message is seen. See :rfc:`4253#section-7.1` for
   details.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :cookie: The SSH_MSG_KEXINIT cookie - a random value generated by
      the sender.
   

   :capabilities: The list of algorithms and languages that the sender
      advertises support for, in order of preference.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh_client_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`string`)

   An :abbr:`SSH (Secure Shell)` Protocol Version Exchange message
   from the client. This contains an identification string that's used
   for version identification. See :rfc:`4253#section-4.2` for
   details.
   

   :c: The connection over which the message was sent.
   

   :version: The identification string
   
   .. bro:see:: ssh_server_version ssh_auth_successful ssh_auth_failed
      ssh_auth_result ssh_auth_attempted ssh_capabilities
      ssh2_server_host_key ssh1_server_host_key ssh_server_host_key
      ssh_encrypted_packet ssh2_dh_server_params ssh2_gss_error
      ssh2_ecc_key

.. bro:id:: ssh_encrypted_packet

   :Type: :bro:type:`event` (c: :bro:type:`connection`, orig: :bro:type:`bool`, len: :bro:type:`count`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   encrypted packet is seen. This event is not handled by default, but
   is provided for heuristic analysis scripts. Note that you have to set
   :bro:id:`SSH::disable_analyzer_after_detection` to false to use this
   event. This carries a performance penalty.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :orig: Whether the packet was sent by the originator of the TCP
      connection.
   

   :len: The length of the :abbr:`SSH (Secure Shell)` payload, in
      bytes. Note that this ignores reassembly, as this is unknown.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh1_server_host_key ssh_server_host_key ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh_server_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`string`)

   An :abbr:`SSH (Secure Shell)` Protocol Version Exchange message
   from the server. This contains an identification string that's used
   for version identification. See :rfc:`4253#section-4.2` for
   details.
   

   :c: The connection over which the message was sent.
   

   :version: The identification string
   
   .. bro:see:: ssh_client_version ssh_auth_successful ssh_auth_failed
      ssh_auth_result ssh_auth_attempted ssh_capabilities
      ssh2_server_host_key ssh1_server_host_key ssh_server_host_key
      ssh_encrypted_packet ssh2_dh_server_params ssh2_gss_error
      ssh2_ecc_key


