:tocdepth: 3

base/protocols/postgresql/main.zeek
===================================
.. zeek:namespace:: PostgreSQL

Implements base functionality for PostgreSQL analysis.

:Namespace: PostgreSQL
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/postgresql/consts.zeek </scripts/base/protocols/postgresql/consts.zeek>`, :doc:`base/protocols/postgresql/spicy-events.zeek </scripts/base/protocols/postgresql/spicy-events.zeek>`

Summary
~~~~~~~
State Variables
###############
================================================================== =
:zeek:id:`PostgreSQL::ports`: :zeek:type:`set` :zeek:attr:`&redef` 
================================================================== =

Types
#####
===================================================== ===============================================================
:zeek:type:`PostgreSQL::Info`: :zeek:type:`record`    Record type containing the column fields of the PostgreSQL log.
:zeek:type:`PostgreSQL::State`: :zeek:type:`record`   
:zeek:type:`PostgreSQL::Version`: :zeek:type:`record` 
===================================================== ===============================================================

Redefinitions
#############
==================================================================== =========================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              Log stream identifier.
                                                                     
                                                                     * :zeek:enum:`PostgreSQL::LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       postgresql: :zeek:type:`PostgreSQL::Info` :zeek:attr:`&optional`
                                                                     
                                                                       postgresql_state: :zeek:type:`PostgreSQL::State` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =========================================================================

Events
######
========================================================= =====================================
:zeek:id:`PostgreSQL::log_postgresql`: :zeek:type:`event` Default hook into PostgreSQL logging.
========================================================= =====================================

Hooks
#####
========================================================================== =
:zeek:id:`PostgreSQL::finalize_postgresql`: :zeek:type:`Conn::RemovalHook` 
========================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: PostgreSQL::ports
   :source-code: base/protocols/postgresql/main.zeek 65 65

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            5432/tcp
         }



Types
#####
.. zeek:type:: PostgreSQL::Info
   :source-code: base/protocols/postgresql/main.zeek 20 49

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when the activity happened.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      user: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         The user as found in the StartupMessage.

      database: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         The database as found in the StartupMessage.

      application_name: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         The application name as found in the StartupMessage.

      frontend: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      frontend_arg: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      backend: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      backend_arg: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      success: :zeek:type:`bool` :zeek:attr:`&optional` :zeek:attr:`&log`

      rows: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`

   Record type containing the column fields of the PostgreSQL log.

.. zeek:type:: PostgreSQL::State
   :source-code: base/protocols/postgresql/main.zeek 51 58

   :Type: :zeek:type:`record`

      version: :zeek:type:`PostgreSQL::Version` :zeek:attr:`&optional`

      user: :zeek:type:`string` :zeek:attr:`&optional`

      database: :zeek:type:`string` :zeek:attr:`&optional`

      application_name: :zeek:type:`string` :zeek:attr:`&optional`

      rows: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      errors: :zeek:type:`vector` of :zeek:type:`string`


.. zeek:type:: PostgreSQL::Version
   :source-code: base/protocols/postgresql/main.zeek 14 17

   :Type: :zeek:type:`record`

      major: :zeek:type:`count`

      minor: :zeek:type:`count`


Events
######
.. zeek:id:: PostgreSQL::log_postgresql
   :source-code: base/protocols/postgresql/main.zeek 61 61

   :Type: :zeek:type:`event` (rec: :zeek:type:`PostgreSQL::Info`)

   Default hook into PostgreSQL logging.

Hooks
#####
.. zeek:id:: PostgreSQL::finalize_postgresql
   :source-code: base/protocols/postgresql/main.zeek 243 245

   :Type: :zeek:type:`Conn::RemovalHook`



