:tocdepth: 3

policy/frameworks/storage/backend/sqlite/main.zeek
==================================================
.. zeek:namespace:: Storage::Backend::SQLite


:Namespace: Storage::Backend::SQLite

Summary
~~~~~~~
Types
#####
=================================================================== ===============================================
:zeek:type:`Storage::Backend::SQLite::Options`: :zeek:type:`record` SQLite storage backend support
                                                                    Options record for the built-in SQLite backend.
=================================================================== ===============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Storage::Backend::SQLite::Options
   :source-code: policy/frameworks/storage/backend/sqlite/main.zeek 7 23

   :Type: :zeek:type:`record`

      database_path: :zeek:type:`string`
         Path to the database file on disk. Setting this to ":memory:"
         will tell SQLite to use an in-memory database.

      table_name: :zeek:type:`string`
         Name of the table used for storing data

      tuning_params: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = *{ 	[synchronous] = normal, 	[temp_store] = memory, 	[journal_mode] = WAL }* :zeek:attr:`&optional`
         Key/value table for passing tuning parameters when opening
         the database.  These must be pairs that can be passed to the
         ``pragma`` command in sqlite.

   SQLite storage backend support
   Options record for the built-in SQLite backend.


