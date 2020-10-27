:tocdepth: 3

base/protocols/ftp/main.zeek
============================
.. zeek:namespace:: FTP

The logging this script does is primarily focused on logging FTP commands
along with metadata.  For example, if files are transferred, the argument
will take on the full path that the client is at along with the requested
file name.

:Namespace: FTP
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/ftp/info.zeek </scripts/base/protocols/ftp/info.zeek>`, :doc:`base/protocols/ftp/utils-commands.zeek </scripts/base/protocols/ftp/utils-commands.zeek>`, :doc:`base/protocols/ftp/utils.zeek </scripts/base/protocols/ftp/utils.zeek>`, :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`, :doc:`base/utils/numbers.zeek </scripts/base/utils/numbers.zeek>`, :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`

Summary
~~~~~~~
Runtime Options
###############
===================================================================== ======================================================================
:zeek:id:`FTP::guest_ids`: :zeek:type:`set` :zeek:attr:`&redef`       User IDs that can be considered "anonymous".
:zeek:id:`FTP::logged_commands`: :zeek:type:`set` :zeek:attr:`&redef` List of commands that should have their command/response pairs logged.
===================================================================== ======================================================================

Types
#####
================================================ ===============================================
:zeek:type:`FTP::ReplyCode`: :zeek:type:`record` This record is to hold a parsed FTP reply code.
================================================ ===============================================

Redefinitions
#############
==================================================================== ========================================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              The FTP protocol logging stream identifier.
                                                                     
                                                                     * :zeek:enum:`FTP::LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       ftp: :zeek:type:`FTP::Info` :zeek:attr:`&optional`
                                                                     
                                                                       ftp_data_reuse: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ========================================================================================

Events
######
=========================================== ==============================================================
:zeek:id:`FTP::log_ftp`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`FTP::Info`
                                            record as it is sent on to the logging framework.
=========================================== ==============================================================

Hooks
#####
============================================================ =============================================
:zeek:id:`FTP::finalize_ftp`: :zeek:type:`Conn::RemovalHook` FTP finalization hook.
:zeek:id:`FTP::finalize_ftp_data`: :zeek:type:`hook`         FTP data finalization hook.
:zeek:id:`FTP::log_policy`: :zeek:type:`Log::PolicyHook`     A default logging policy hook for the stream.
============================================================ =============================================

Functions
#########
=========================================================== =====================================================================
:zeek:id:`FTP::parse_ftp_reply_code`: :zeek:type:`function` Parse FTP reply codes into the three constituent single digit values.
=========================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: FTP::guest_ids

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "guest",
            "anonymous",
            "ftpuser",
            "ftp"
         }


   User IDs that can be considered "anonymous".

.. zeek:id:: FTP::logged_commands

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "ACCT",
            "DELE",
            "APPE",
            "RETR",
            "PORT",
            "STOR",
            "EPRT",
            "PASV",
            "STOU",
            "EPSV"
         }


   List of commands that should have their command/response pairs logged.

Types
#####
.. zeek:type:: FTP::ReplyCode

   :Type: :zeek:type:`record`

      x: :zeek:type:`count`

      y: :zeek:type:`count`

      z: :zeek:type:`count`

   This record is to hold a parsed FTP reply code.  For example, for the
   201 status code, the digits would be parsed as: x->2, y->0, z->1.

Events
######
.. zeek:id:: FTP::log_ftp

   :Type: :zeek:type:`event` (rec: :zeek:type:`FTP::Info`)

   Event that can be handled to access the :zeek:type:`FTP::Info`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: FTP::finalize_ftp

   :Type: :zeek:type:`Conn::RemovalHook`

   FTP finalization hook.  Remaining FTP info may get logged when it's called.

.. zeek:id:: FTP::finalize_ftp_data

   :Type: :zeek:type:`hook` (c: :zeek:type:`connection`) : :zeek:type:`bool`

   FTP data finalization hook.  Expected FTP data channel state may
   get purged when called.

.. zeek:id:: FTP::log_policy

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

Functions
#########
.. zeek:id:: FTP::parse_ftp_reply_code

   :Type: :zeek:type:`function` (code: :zeek:type:`count`) : :zeek:type:`FTP::ReplyCode`

   Parse FTP reply codes into the three constituent single digit values.


