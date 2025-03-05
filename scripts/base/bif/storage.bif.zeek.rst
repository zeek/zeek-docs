:tocdepth: 3

base/bif/storage.bif.zeek
=========================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Storage
.. zeek:namespace:: Storage::Async
.. zeek:namespace:: Storage::Sync


:Namespaces: GLOBAL, Storage, Storage::Async, Storage::Sync

Summary
~~~~~~~
Events
######
============================================================== =============================================================================
:zeek:id:`Storage::connection_established`: :zeek:type:`event` Generated automatically when a new backend connection is opened successfully.
:zeek:id:`Storage::connection_lost`: :zeek:type:`event`        May be generated when a backend connection is lost, both normally and
                                                               unexpectedly.
============================================================== =============================================================================

Functions
#########
================================================================= =
:zeek:id:`Storage::Async::__close_backend`: :zeek:type:`function` 
:zeek:id:`Storage::Async::__erase`: :zeek:type:`function`         
:zeek:id:`Storage::Async::__get`: :zeek:type:`function`           
:zeek:id:`Storage::Async::__open_backend`: :zeek:type:`function`  
:zeek:id:`Storage::Async::__put`: :zeek:type:`function`           
:zeek:id:`Storage::Sync::__close_backend`: :zeek:type:`function`  
:zeek:id:`Storage::Sync::__erase`: :zeek:type:`function`          
:zeek:id:`Storage::Sync::__get`: :zeek:type:`function`            
:zeek:id:`Storage::Sync::__open_backend`: :zeek:type:`function`   
:zeek:id:`Storage::Sync::__put`: :zeek:type:`function`            
================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: Storage::connection_established
   :source-code: base/bif/storage.bif.zeek 10 10

   :Type: :zeek:type:`event` (tag: :zeek:type:`string`, config: :zeek:type:`any`)

   Generated automatically when a new backend connection is opened successfully.

.. zeek:id:: Storage::connection_lost
   :source-code: base/bif/storage.bif.zeek 16 16

   :Type: :zeek:type:`event` (tag: :zeek:type:`string`, config: :zeek:type:`any`, reason: :zeek:type:`string`)

   May be generated when a backend connection is lost, both normally and
   unexpectedly. This event depends on the backends implementing handling for
   it, and is not generated automatically by the storage framework.

Functions
#########
.. zeek:id:: Storage::Async::__close_backend
   :source-code: base/bif/storage.bif.zeek 25 25

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Async::__erase
   :source-code: base/bif/storage.bif.zeek 34 34

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Async::__get
   :source-code: base/bif/storage.bif.zeek 31 31

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Async::__open_backend
   :source-code: base/bif/storage.bif.zeek 22 22

   :Type: :zeek:type:`function` (btype: :zeek:type:`Storage::Backend`, config: :zeek:type:`any`, key_type: :zeek:type:`any`, val_type: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Async::__put
   :source-code: base/bif/storage.bif.zeek 28 28

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`, value: :zeek:type:`any`, overwrite: :zeek:type:`bool`, expire_time: :zeek:type:`interval`) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Sync::__close_backend
   :source-code: base/bif/storage.bif.zeek 43 43

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Sync::__erase
   :source-code: base/bif/storage.bif.zeek 52 52

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Sync::__get
   :source-code: base/bif/storage.bif.zeek 49 49

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Sync::__open_backend
   :source-code: base/bif/storage.bif.zeek 40 40

   :Type: :zeek:type:`function` (btype: :zeek:type:`Storage::Backend`, config: :zeek:type:`any`, key_type: :zeek:type:`any`, val_type: :zeek:type:`any`) : :zeek:type:`Storage::OperationResult`


.. zeek:id:: Storage::Sync::__put
   :source-code: base/bif/storage.bif.zeek 46 46

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`, value: :zeek:type:`any`, overwrite: :zeek:type:`bool`, expire_time: :zeek:type:`interval`) : :zeek:type:`Storage::OperationResult`



