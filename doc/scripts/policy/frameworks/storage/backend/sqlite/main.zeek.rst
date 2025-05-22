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
   :source-code: policy/frameworks/storage/backend/sqlite/main.zeek 9 45

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

      pragma_commands: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&ordered` :zeek:attr:`&default` = *{ 	[integrity_check] = , 	[busy_timeout] = 5000, 	[journal_mode] = WAL, 	[synchronous] = normal, 	[temp_store] = memory }* :zeek:attr:`&optional`
         Key/value table for passing pragma commands when opening the database.
         These must be pairs that can be passed to the ``pragma`` command in
         sqlite. The ``integrity_check`` pragma is run automatically and does
         not need to be included here. For pragmas without a second argument,
         set the value to an empty string.

      pragma_timeout: :zeek:type:`interval` :zeek:attr:`&default` = ``500.0 msecs`` :zeek:attr:`&optional`
         The total amount of time that an SQLite backend will spend attempting
         to run an individual pragma command before giving up and returning an
         initialization error. Setting this to zero will result in the backend
         attempting forever until success.

      pragma_wait_on_busy: :zeek:type:`interval` :zeek:attr:`&default` = ``5.0 msecs`` :zeek:attr:`&optional`
         The amount of time that at SQLite backend will wait between failures
         to run an individual pragma command.

   Options record for the built-in SQLite backend.


