:tocdepth: 3

base/bif/storage.bif.zeek
=========================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Storage


:Namespaces: GLOBAL, Storage

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
========================================================== =
:zeek:id:`Storage::__close_backend`: :zeek:type:`function` 
:zeek:id:`Storage::__erase`: :zeek:type:`function`         
:zeek:id:`Storage::__get`: :zeek:type:`function`           
:zeek:id:`Storage::__open_backend`: :zeek:type:`function`  
:zeek:id:`Storage::__put`: :zeek:type:`function`           
========================================================== =


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
.. zeek:id:: Storage::__close_backend
   :source-code: base/bif/storage.bif.zeek 20 20

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle) : :zeek:type:`bool`


.. zeek:id:: Storage::__erase
   :source-code: base/bif/storage.bif.zeek 29 29

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`, async_mode: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`bool`


.. zeek:id:: Storage::__get
   :source-code: base/bif/storage.bif.zeek 26 26

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`, async_mode: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`any`


.. zeek:id:: Storage::__open_backend
   :source-code: base/bif/storage.bif.zeek 17 17

   :Type: :zeek:type:`function` (btype: :zeek:type:`Storage::Backend`, config: :zeek:type:`any`, key_type: :zeek:type:`any`, val_type: :zeek:type:`any`) : :zeek:type:`opaque` of Storage::BackendHandle


.. zeek:id:: Storage::__put
   :source-code: base/bif/storage.bif.zeek 23 23

   :Type: :zeek:type:`function` (backend: :zeek:type:`opaque` of Storage::BackendHandle, key: :zeek:type:`any`, value: :zeek:type:`any`, overwrite: :zeek:type:`bool`, expire_time: :zeek:type:`interval`, async_mode: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`) : :zeek:type:`bool`



