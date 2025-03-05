:tocdepth: 3

policy/frameworks/storage/backend/redis/main.zeek
=================================================
.. zeek:namespace:: Storage::Backend::Redis


:Namespace: Storage::Backend::Redis

Summary
~~~~~~~
Types
#####
================================================================== ==============================================
:zeek:type:`Storage::Backend::Redis::Options`: :zeek:type:`record` Redis storage backend support
                                                                   Options record for the built-in Redis backend.
================================================================== ==============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Storage::Backend::Redis::Options
   :source-code: policy/frameworks/storage/backend/redis/main.zeek 7 34

   :Type: :zeek:type:`record`

      server_addr: :zeek:type:`string`

      server_port: :zeek:type:`port`

      server_unix_socket: :zeek:type:`string`

      key_prefix: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

      async_mode: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`

   Redis storage backend support
   Options record for the built-in Redis backend.


