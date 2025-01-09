:tocdepth: 3

base/frameworks/storage/main.zeek
=================================
.. zeek:namespace:: Storage

The storage framework provides a way to store long-term data to disk.

:Namespace: Storage
:Imports: :doc:`base/bif/storage.bif.zeek </scripts/base/bif/storage.bif.zeek>`

Summary
~~~~~~~
Types
#####
======================================================== ===============================================
:zeek:type:`Storage::PutArgs`: :zeek:type:`record`       Record for passing arguments to ``put``.
:zeek:type:`Storage::RedisOptions`: :zeek:type:`record`  Options record for the built-in Redis backend.
:zeek:type:`Storage::SqliteOptions`: :zeek:type:`record` Options record for the built-in SQLite backend.
:zeek:type:`Storage::Backend`: :zeek:type:`enum`         
======================================================== ===============================================

Functions
#########
======================================================== ===============================================================
:zeek:id:`Storage::close_backend`: :zeek:type:`function` Closes an existing backend connection.
:zeek:id:`Storage::erase`: :zeek:type:`function`         Erases an entry from the backend.
:zeek:id:`Storage::get`: :zeek:type:`function`           Gets an entry from the backend.
:zeek:id:`Storage::open_backend`: :zeek:type:`function`  Opens a new backend connection based on a configuration object.
:zeek:id:`Storage::put`: :zeek:type:`function`           Inserts a new entry into a backend.
======================================================== ===============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Storage::PutArgs
   :source-code: base/frameworks/storage/main.zeek 9 35

   :Type: :zeek:type:`record`

      backend: :zeek:type:`opaque` of Storage::BackendHandle

      key: :zeek:type:`any`

      value: :zeek:type:`any`

      overwrite: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      expire_time: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`

      async_mode: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`

   Record for passing arguments to ``put``.

.. zeek:type:: Storage::RedisOptions
   :source-code: base/frameworks/storage/main.zeek 56 81

   :Type: :zeek:type:`record`

      server_addr: :zeek:type:`string`

      server_port: :zeek:type:`port`

      server_unix_socket: :zeek:type:`string`

      key_prefix: :zeek:type:`string`

      async_mode: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`

   Options record for the built-in Redis backend.

.. zeek:type:: Storage::SqliteOptions
   :source-code: base/frameworks/storage/main.zeek 38 53

   :Type: :zeek:type:`record`

      database_path: :zeek:type:`string`
         Path to the database file on disk

      table_name: :zeek:type:`string`
         Name of the table used for storing data

      tuning_params: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = *{ 	[synchronous] = normal, 	[temp_store] = memory, 	[journal_mode] = WAL }* :zeek:attr:`&optional`
         Key/value table for passing tuning parameters when opening
         the database.  These must be pairs that can be passed to the
         ``pragma`` command in sqlite.

   Options record for the built-in SQLite backend.

.. zeek:type:: Storage::Backend

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Storage::SQLITE Storage::Backend


Functions
#########
.. zeek:id:: Storage::close_backend
   :source-code: base/frameworks/storage/main.zeek 152 155

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`bool`

   Closes an existing backend connection.
   

   :param backend: A handle to a backend connection.
   

   :returns: A boolean indicating success or failure of the operation.

.. zeek:id:: Storage::erase
   :source-code: base/frameworks/storage/main.zeek 167 170

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`, async_mode: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Erases an entry from the backend.
   

   :param backend: A handle to a backend connection.
   

   :param key: The key to erase.
   
   async_mode Indicates whether this operation should happen
   asynchronously. If this is T, the call must happen as part of a
   :zeek:see::`when` statement.
   

   :returns: A boolean indicating success or failure of the operation.
   Type comparison failures against the types passed to
   :zeek:see::`Storage::open_backend` for the backend will cause false
   to be returned.

.. zeek:id:: Storage::get
   :source-code: base/frameworks/storage/main.zeek 162 165

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`, async_mode: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`any`

   Gets an entry from the backend.
   

   :param backend: A handle to a backend connection.
   

   :param key: The key to look up.
   
   async_mode Indicates whether this operation should happen
   asynchronously. If this is T, the call must happen as part of a

   :param zeek:see:`when` statement.
   

   :returns: A boolean indicating success or failure of the operation.
   Type comparison failures against the types passed to
   :zeek:see::`Storage::open_backend` for the backend will cause false
   to be returned.

.. zeek:id:: Storage::open_backend
   :source-code: base/frameworks/storage/main.zeek 147 150

   :Type: :zeek:type:`function` (btype: :zeek:type:`Storage::Backend`, config: :zeek:type:`any`, key_type: :zeek:type:`any`, val_type: :zeek:type:`any`) : :zeek:type:`opaque` of Storage::BackendHandle

   Opens a new backend connection based on a configuration object.
   

   :param btype: A tag indicating what type of backend should be opened.
   

   :param config: A record containing the configuration for the connection.
   

   :param key_type: The Val type of the key being stored.
   

   :param val_type: The Val type of the key being stored.
   

   :returns: A handle to the new backend connection, or null if the connection failed.

.. zeek:id:: Storage::put
   :source-code: base/frameworks/storage/main.zeek 157 160

   :Type: :zeek:type:`function` (args: :zeek:type:`Storage::PutArgs`) : :zeek:type:`bool`

   Inserts a new entry into a backend.
   

   :returns: A boolean indicating success or failure of the
   operation. Type comparison failures against the types passed to
   :zeek:see:`Storage::open_backend` for the backend will cause false to
   be returned.


