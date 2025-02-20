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
====================================================================== =
:zeek:id:`Storage::storage_connection_established`: :zeek:type:`event` 
:zeek:id:`Storage::storage_connection_lost`: :zeek:type:`event`        
====================================================================== =

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
.. zeek:id:: Storage::storage_connection_established
   :source-code: base/bif/storage.bif.zeek 10 10

   :Type: :zeek:type:`event` ()


.. zeek:id:: Storage::storage_connection_lost
   :source-code: base/bif/storage.bif.zeek 14 14

   :Type: :zeek:type:`event` ()


Functions
#########
.. zeek:id:: Storage::Async::__close_backend
   :source-code: base/bif/storage.bif.zeek 23 23

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`bool`


.. zeek:id:: Storage::Async::__erase
   :source-code: base/bif/storage.bif.zeek 32 32

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Storage::Async::__get
   :source-code: base/bif/storage.bif.zeek 29 29

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`val_result`


.. zeek:id:: Storage::Async::__open_backend
   :source-code: base/bif/storage.bif.zeek 20 20

   :Type: :zeek:type:`function` (btype: :zeek:type:`Storage::Backend`, config: :zeek:type:`any`, key_type: :zeek:type:`any`, val_type: :zeek:type:`any`) : :zeek:type:`opaque` of Storage::BackendHandle


.. zeek:id:: Storage::Async::__put
   :source-code: base/bif/storage.bif.zeek 26 26

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`, value: :zeek:type:`any`, overwrite: :zeek:type:`bool`, expire_time: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Storage::Sync::__close_backend
   :source-code: base/bif/storage.bif.zeek 41 41

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`bool`


.. zeek:id:: Storage::Sync::__erase
   :source-code: base/bif/storage.bif.zeek 50 50

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`bool`


.. zeek:id:: Storage::Sync::__get
   :source-code: base/bif/storage.bif.zeek 47 47

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`) : :zeek:type:`val_result`


.. zeek:id:: Storage::Sync::__open_backend
   :source-code: base/bif/storage.bif.zeek 38 38

   :Type: :zeek:type:`function` (btype: :zeek:type:`Storage::Backend`, config: :zeek:type:`any`, key_type: :zeek:type:`any`, val_type: :zeek:type:`any`) : :zeek:type:`opaque` of Storage::BackendHandle


.. zeek:id:: Storage::Sync::__put
   :source-code: base/bif/storage.bif.zeek 44 44

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`, value: :zeek:type:`any`, overwrite: :zeek:type:`bool`, expire_time: :zeek:type:`interval`) : :zeek:type:`bool`



