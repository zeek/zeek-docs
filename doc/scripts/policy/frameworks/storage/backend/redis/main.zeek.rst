:tocdepth: 3

policy/frameworks/storage/backend/redis/main.zeek
=================================================
.. zeek:namespace:: Storage::Backend::Redis

Redis storage backend support

:Namespace: Storage::Backend::Redis
:Imports: :doc:`base/frameworks/storage/main.zeek </scripts/base/frameworks/storage/main.zeek>`

Summary
~~~~~~~
Types
#####
================================================================== ==============================================
:zeek:type:`Storage::Backend::Redis::Options`: :zeek:type:`record` Options record for the built-in Redis backend.
================================================================== ==============================================

Redefinitions
#############
========================================================= =============================================================================
:zeek:type:`Storage::BackendOptions`: :zeek:type:`record` 
                                                          
                                                          :New Fields: :zeek:type:`Storage::BackendOptions`
                                                          
                                                            redis: :zeek:type:`Storage::Backend::Redis::Options` :zeek:attr:`&optional`
========================================================= =============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Storage::Backend::Redis::Options
   :source-code: policy/frameworks/storage/backend/redis/main.zeek 9 25

   :Type: :zeek:type:`record`

      server_host: :zeek:type:`string` :zeek:attr:`&optional`

      server_port: :zeek:type:`port` :zeek:attr:`&default` = ``6379/tcp`` :zeek:attr:`&optional`

      server_unix_socket: :zeek:type:`string` :zeek:attr:`&optional`

      key_prefix: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

   Options record for the built-in Redis backend.


