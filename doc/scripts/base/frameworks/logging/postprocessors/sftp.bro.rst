:tocdepth: 3

base/frameworks/logging/postprocessors/sftp.bro
===============================================
.. bro:namespace:: Log

This script defines a postprocessing function that can be applied
to a logging filter in order to automatically SFTP
a log stream (or a subset of it) to a remote host at configurable
rotation time intervals.  Generally, to use this functionality
you must handle the :bro:id:`bro_init` event and do the following
in your handler:

1) Create a new :bro:type:`Log::Filter` record that defines a name/path,
   rotation interval, and set the ``postprocessor`` to
   :bro:id:`Log::sftp_postprocessor`.
2) Add the filter to a logging stream using :bro:id:`Log::add_filter`.
3) Add a table entry to :bro:id:`Log::sftp_destinations` for the filter's
   writer/path pair which defines a set of :bro:type:`Log::SFTPDestination`
   records.

:Namespace: Log

Summary
~~~~~~~
Redefinable Options
###################
=============================================================================== ================================================================
:bro:id:`Log::sftp_rotation_date_format`: :bro:type:`string` :bro:attr:`&redef` Default naming format for timestamps embedded into log filenames
                                                                                that use the SFTP rotator.
=============================================================================== ================================================================

State Variables
###############
=================================================== =======================================================================
:bro:id:`Log::sftp_destinations`: :bro:type:`table` A table indexed by a particular log writer and filter path, that yields
                                                    a set of remote destinations.
=================================================== =======================================================================

Types
#####
==================================================== =======================================================================
:bro:type:`Log::SFTPDestination`: :bro:type:`record` A container that describes the remote destination for the SFTP command,
                                                     comprised of the username, host, and path at which to upload the file.
==================================================== =======================================================================

Functions
#########
======================================================= ============================================================
:bro:id:`Log::sftp_postprocessor`: :bro:type:`function` Securely transfers the rotated log to all the remote hosts
                                                        defined in :bro:id:`Log::sftp_destinations` and then deletes
                                                        the local copy of the rotated log.
======================================================= ============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: Log::sftp_rotation_date_format

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"%Y-%m-%d-%H-%M-%S"``

   Default naming format for timestamps embedded into log filenames
   that use the SFTP rotator.

State Variables
###############
.. bro:id:: Log::sftp_destinations

   :Type: :bro:type:`table` [:bro:type:`Log::Writer`, :bro:type:`string`] of :bro:type:`set` [:bro:type:`Log::SFTPDestination`]
   :Default: ``{}``

   A table indexed by a particular log writer and filter path, that yields
   a set of remote destinations.  The :bro:id:`Log::sftp_postprocessor`
   function queries this table upon log rotation and performs a secure
   transfer of the rotated log to each destination in the set.  This
   table can be modified at run-time.

Types
#####
.. bro:type:: Log::SFTPDestination

   :Type: :bro:type:`record`

      user: :bro:type:`string`
         The remote user to log in as.  A trust mechanism should be
         pre-established.

      host: :bro:type:`string`
         The remote host to which to transfer logs.

      host_port: :bro:type:`count` :bro:attr:`&default` = ``22`` :bro:attr:`&optional`
         The port to connect to. Defaults to 22

      path: :bro:type:`string`
         The path/directory on the remote host to send logs.

   A container that describes the remote destination for the SFTP command,
   comprised of the username, host, and path at which to upload the file.

Functions
#########
.. bro:id:: Log::sftp_postprocessor

   :Type: :bro:type:`function` (info: :bro:type:`Log::RotationInfo`) : :bro:type:`bool`

   Securely transfers the rotated log to all the remote hosts
   defined in :bro:id:`Log::sftp_destinations` and then deletes
   the local copy of the rotated log.  It's not active when
   reading from trace files.
   

   :info: A record holding meta-information about the log file to be
         postprocessed.
   

   :returns: True if sftp system command was initiated or
            if no destination was configured for the log as described
            by *info*.


