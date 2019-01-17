:orphan:

Package: base/frameworks/logging/postprocessors
===============================================

Support for postprocessors in the logging framework.

:doc:`/scripts/base/frameworks/logging/postprocessors/__load__.bro`


:doc:`/scripts/base/frameworks/logging/postprocessors/scp.bro`

   This script defines a postprocessing function that can be applied
   to a logging filter in order to automatically SCP (secure copy)
   a log stream (or a subset of it) to a remote host at configurable
   rotation time intervals.  Generally, to use this functionality
   you must handle the :bro:id:`bro_init` event and do the following
   in your handler:
   
   1) Create a new :bro:type:`Log::Filter` record that defines a name/path,
      rotation interval, and set the ``postprocessor`` to
      :bro:id:`Log::scp_postprocessor`.
   2) Add the filter to a logging stream using :bro:id:`Log::add_filter`.
   3) Add a table entry to :bro:id:`Log::scp_destinations` for the filter's
      writer/path pair which defines a set of :bro:type:`Log::SCPDestination`
      records.

:doc:`/scripts/base/frameworks/logging/postprocessors/sftp.bro`

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

