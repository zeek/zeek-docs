:tocdepth: 3

policy/frameworks/storage/backend/sqlite/main.zeek
==================================================
.. zeek:namespace:: Storage::Backend::SQLite

SQLite storage backend support

:Namespace: Storage::Backend::SQLite
:Imports: :doc:`base/frameworks/storage/main.zeek </scripts/base/frameworks/storage/main.zeek>`

Summary
~~~~~~~
Types
#####
=================================================================== ===============================================
:zeek:type:`Storage::Backend::SQLite::Options`: :zeek:type:`record` Options record for the built-in SQLite backend.
=================================================================== ===============================================

Redefinitions
#############
========================================================= ===============================================================================
:zeek:type:`Storage::BackendOptions`: :zeek:type:`record` 
                                                          
                                                          :New Fields: :zeek:type:`Storage::BackendOptions`
                                                          
                                                            sqlite: :zeek:type:`Storage::Backend::SQLite::Options` :zeek:attr:`&optional`
========================================================= ===============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Storage::Backend::SQLite::Options
   :source-code: policy/frameworks/storage/backend/sqlite/main.zeek 9 31

   :Type: :zeek:type:`record`

      database_path: :zeek:type:`string`
         Path to the database file on disk. Setting this to ":memory:" will tell
         SQLite to use an in-memory database. Relative paths will be opened
         relative to the directory where Zeek was started from. Zeek will not
         create intermediate directories if they do not already exist. See
         https://www.sqlite.org/c3ref/open.html for more rules on paths that can
         be passed here.

      table_name: :zeek:type:`string`
         Name of the table used for storing data. It is possible to use the same
         database file for two separate tables, as long as the this value is
         different between the two.

      tuning_params: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = *{ 	[synchronous] = normal, 	[temp_store] = memory, 	[journal_mode] = WAL }* :zeek:attr:`&optional`
         Key/value table for passing tuning parameters when opening the
         database.  These must be pairs that can be passed to the ``pragma``
         command in sqlite.

   Options record for the built-in SQLite backend.


