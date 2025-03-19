:tocdepth: 3

base/frameworks/storage/main.zeek
=================================
.. zeek:namespace:: Storage

The storage framework provides a way to store long-term data to disk.

:Namespace: Storage

Summary
~~~~~~~
Types
#####
========================================================= ===================================================================
:zeek:type:`Storage::BackendOptions`: :zeek:type:`record` Base record for backend options that can be passed to
                                                          :zeek:see:`Storage::Async::open_backend` and
                                                          :zeek:see:`Storage::Sync::open_backend`.
:zeek:type:`Storage::PutArgs`: :zeek:type:`record`        Record for passing arguments to :zeek:see:`Storage::Async::put` and
                                                          :zeek:see:`Storage::Sync::put`.
:zeek:type:`Storage::Backend`: :zeek:type:`enum`          
========================================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Storage::BackendOptions
   :source-code: base/frameworks/storage/main.zeek 10 11

   :Type: :zeek:type:`record`

      redis: :zeek:type:`Storage::Backend::Redis::Options` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/storage/backend/redis/main.zeek` is loaded)


      sqlite: :zeek:type:`Storage::Backend::SQLite::Options` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/storage/backend/sqlite/main.zeek` is loaded)


   Base record for backend options that can be passed to
   :zeek:see:`Storage::Async::open_backend` and
   :zeek:see:`Storage::Sync::open_backend`. Backend plugins can redef this record
   to add relevant fields to it.

.. zeek:type:: Storage::PutArgs
   :source-code: base/frameworks/storage/main.zeek 14 28

   :Type: :zeek:type:`record`

      key: :zeek:type:`any`

      value: :zeek:type:`any`

      overwrite: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`

      expire_time: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`

   Record for passing arguments to :zeek:see:`Storage::Async::put` and
   :zeek:see:`Storage::Sync::put`.

.. zeek:type:: Storage::Backend

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Storage::SQLITE Storage::Backend



