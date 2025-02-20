:tocdepth: 3

base/frameworks/storage/async.zeek
==================================
.. zeek:namespace:: Storage::Async

Asynchronous operation methods for the storage framework. These methods must
be called as part of a :zeek:see:`when` statement. An error will be returned
otherwise.

:Namespace: Storage::Async
:Imports: :doc:`base/frameworks/storage/main.zeek </scripts/base/frameworks/storage/main.zeek>`

Summary
~~~~~~~
Functions
#########
=============================================================== ==============================================================================
:zeek:id:`Storage::Async::close_backend`: :zeek:type:`function` Closes an existing backend connection asynchronously.
:zeek:id:`Storage::Async::erase`: :zeek:type:`function`         Erases an entry from the backend asynchronously.
:zeek:id:`Storage::Async::get`: :zeek:type:`function`           Gets an entry from the backend asynchronously.
:zeek:id:`Storage::Async::open_backend`: :zeek:type:`function`  Opens a new backend connection based on a configuration object asynchronously.
:zeek:id:`Storage::Async::put`: :zeek:type:`function`           Inserts a new entry into a backend asynchronously.
=============================================================== ==============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Storage::Async::close_backend
   :source-code: base/frameworks/storage/async.zeek 79 82

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`bool`

   Closes an existing backend connection asynchronously.
   

   :param backend: A handle to a backend connection.
   

   :returns: A boolean indicating success or failure of the operation.

.. zeek:id:: Storage::Async::erase
   :source-code: base/frameworks/storage/async.zeek 94 97

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`bool`

   Erases an entry from the backend asynchronously.
   

   :param backend: A handle to a backend connection.
   

   :param key: The key to erase.
   

   :returns: A boolean indicating success or failure of the operation.
            Type comparison failures against the types passed to
            :zeek:see:`Storage::open_backend` for the backend will cause
            false to be returned.

.. zeek:id:: Storage::Async::get
   :source-code: base/frameworks/storage/async.zeek 89 92

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`val_result`

   Gets an entry from the backend asynchronously.
   

   :param backend: A handle to a backend connection.
   

   :param key: The key to look up.
   

   :returns: A record containing the value requested or an error string. The caller
            should check the validity of the value before attempting to use it. If
            the value is unset, an error string may be available to describe the
            failure.

.. zeek:id:: Storage::Async::open_backend
   :source-code: base/frameworks/storage/async.zeek 74 77

   :Type: :zeek:type:`function` (btype: :zeek:type:`Storage::Backend`, config: :zeek:type:`any`, key_type: :zeek:type:`any`, val_type: :zeek:type:`any`) : :zeek:type:`opaque` of Storage::BackendHandle

   Opens a new backend connection based on a configuration object asynchronously.
   

   :param btype: A tag indicating what type of backend should be opened. These are defined
          by the backend plugins loaded.
   

   :param config: A record containing the configuration for the connection.
   

   :param key_type: The script-level type of keys stored in the backend. Used for
             validation of keys passed to other framework methods.
   

   :param val_type: The script-level type of keys stored in the backend. Used for
             validation of values passed to :zeek:see:`Storage::put` as well as
             for type conversions for return values from
             :zeek:see:`Storage::get`.
   

   :returns: A handle to the new backend connection or F if the
            connection failed.

.. zeek:id:: Storage::Async::put
   :source-code: base/frameworks/storage/async.zeek 84 87

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, args: :zeek:type:`Storage::PutArgs`) : :zeek:type:`bool`

   Inserts a new entry into a backend asynchronously.
   

   :param backend: A handle to a backend connection.
   

   :param args: A :zeek:see:`Storage::PutArgs` record containing the arguments for the operation.
   

   :returns: A boolean indicating success or failure of the
            operation. Type comparison failures against the types passed
            to :zeek:see:`Storage::open_backend` for the backend will
            cause false to be returned.


