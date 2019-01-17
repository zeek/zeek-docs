:orphan:

Package: base/frameworks/reporter
=================================

This framework is intended to create an output and filtering path for
internally generated messages/warnings/errors.

:doc:`/scripts/base/frameworks/reporter/__load__.bro`


:doc:`/scripts/base/frameworks/reporter/main.bro`

   This framework is intended to create an output and filtering path for
   internal messages/warnings/errors.  It should typically be loaded to
   log such messages to a file in a standard way.  For the options to
   toggle whether messages are additionally written to STDERR, see
   :bro:see:`Reporter::info_to_stderr`,
   :bro:see:`Reporter::warnings_to_stderr`, and
   :bro:see:`Reporter::errors_to_stderr`.
   
   Note that this framework deals with the handling of internally generated
   reporter messages, for the interface
   into actually creating reporter messages from the scripting layer, use
   the built-in functions in :doc:`/scripts/base/bif/reporter.bif.bro`.

