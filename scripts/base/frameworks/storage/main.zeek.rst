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
================================================== =========================================================
:zeek:type:`Storage::PutArgs`: :zeek:type:`record` Record for passing arguments to :zeek:see:`Storage::put`.
:zeek:type:`Storage::Backend`: :zeek:type:`enum`   
================================================== =========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Storage::PutArgs
   :source-code: base/frameworks/storage/main.zeek 9 23

   :Type: :zeek:type:`record`

      key: :zeek:type:`any`

      value: :zeek:type:`any`

      overwrite: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      expire_time: :zeek:type:`interval` :zeek:attr:`&default` = ``0 secs`` :zeek:attr:`&optional`

   Record for passing arguments to :zeek:see:`Storage::put`.

.. zeek:type:: Storage::Backend

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Storage::REDIS Storage::Backend

      .. zeek:enum:: Storage::SQLITE Storage::Backend



