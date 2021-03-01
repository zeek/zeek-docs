:tocdepth: 3

base/bif/reporter.bif.zeek
==========================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Reporter

The reporter built-in functions allow for the scripting layer to
generate messages of varying severity.  If no event handlers
exist for reporter messages, the messages are output to stderr.
If event handlers do exist, it's assumed they take care of determining
how/where to output the messages.

See :doc:`/scripts/base/frameworks/reporter/main.zeek` for a convenient
reporter message logging framework.

:Namespaces: GLOBAL, Reporter

Summary
~~~~~~~
Functions
#########
========================================================================== ========================================================================
:zeek:id:`Reporter::conn_weird`: :zeek:type:`function`                     Generates a "conn" weird.
:zeek:id:`Reporter::error`: :zeek:type:`function`                          Generates a non-fatal error indicative of a definite problem that should
                                                                           be addressed.
:zeek:id:`Reporter::fatal`: :zeek:type:`function`                          Generates a fatal error on stderr and terminates program execution.
:zeek:id:`Reporter::fatal_error_with_core`: :zeek:type:`function`          Generates a fatal error on stderr and terminates program execution
                                                                           after dumping a core file
:zeek:id:`Reporter::file_weird`: :zeek:type:`function`                     Generates a "file" weird.
:zeek:id:`Reporter::flow_weird`: :zeek:type:`function`                     Generates a "flow" weird.
:zeek:id:`Reporter::get_weird_sampling_duration`: :zeek:type:`function`    Gets the current weird sampling duration.
:zeek:id:`Reporter::get_weird_sampling_global_list`: :zeek:type:`function` Gets the weird sampling global list
:zeek:id:`Reporter::get_weird_sampling_rate`: :zeek:type:`function`        Gets the current weird sampling rate.
:zeek:id:`Reporter::get_weird_sampling_threshold`: :zeek:type:`function`   Gets the current weird sampling threshold
:zeek:id:`Reporter::get_weird_sampling_whitelist`: :zeek:type:`function`   Gets the weird sampling whitelist
:zeek:id:`Reporter::info`: :zeek:type:`function`                           Generates an informational message.
:zeek:id:`Reporter::net_weird`: :zeek:type:`function`                      Generates a "net" weird.
:zeek:id:`Reporter::set_weird_sampling_duration`: :zeek:type:`function`    Sets the current weird sampling duration.
:zeek:id:`Reporter::set_weird_sampling_global_list`: :zeek:type:`function` Sets the weird sampling global list
:zeek:id:`Reporter::set_weird_sampling_rate`: :zeek:type:`function`        Sets the weird sampling rate.
:zeek:id:`Reporter::set_weird_sampling_threshold`: :zeek:type:`function`   Sets the current weird sampling threshold
:zeek:id:`Reporter::set_weird_sampling_whitelist`: :zeek:type:`function`   Sets the weird sampling whitelist
:zeek:id:`Reporter::warning`: :zeek:type:`function`                        Generates a message that warns of a potential problem.
========================================================================== ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Reporter::conn_weird
   :source-code: base/bif/reporter.bif.zeek 95 95

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, c: :zeek:type:`connection`, addl: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`, source: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Generates a "conn" weird.
   

   :name: the name of the weird.
   

   :c: the connection associated with the weird.
   

   :addl: additional information to accompany the weird.
   

   :returns: Always true.

.. zeek:id:: Reporter::error
   :source-code: base/bif/reporter.bif.zeek 46 46

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`bool`

   Generates a non-fatal error indicative of a definite problem that should
   be addressed. Program execution does not terminate.
   

   :msg: The error message to report.
   

   :returns: Always true.
   
   .. zeek:see:: reporter_error

.. zeek:id:: Reporter::fatal
   :source-code: base/bif/reporter.bif.zeek 54 54

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`bool`

   Generates a fatal error on stderr and terminates program execution.
   

   :msg: The error message to report.
   

   :returns: Always true.

.. zeek:id:: Reporter::fatal_error_with_core
   :source-code: base/bif/reporter.bif.zeek 63 63

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`bool`

   Generates a fatal error on stderr and terminates program execution
   after dumping a core file
   

   :msg: The error message to report.
   

   :returns: Always true.

.. zeek:id:: Reporter::file_weird
   :source-code: base/bif/reporter.bif.zeek 107 107

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, f: :zeek:type:`fa_file`, addl: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`, source: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Generates a "file" weird.
   

   :name: the name of the weird.
   

   :f: the file associated with the weird.
   

   :addl: additional information to accompany the weird.
   

   :returns: true if the file was still valid, else false.

.. zeek:id:: Reporter::flow_weird
   :source-code: base/bif/reporter.bif.zeek 83 83

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, orig: :zeek:type:`addr`, resp: :zeek:type:`addr`, addl: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`, source: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Generates a "flow" weird.
   

   :name: the name of the weird.
   

   :orig: the originator host associated with the weird.
   

   :resp: the responder host associated with the weird.
   

   :returns: Always true.

.. zeek:id:: Reporter::get_weird_sampling_duration
   :source-code: base/bif/reporter.bif.zeek 170 170

   :Type: :zeek:type:`function` () : :zeek:type:`interval`

   Gets the current weird sampling duration.
   

   :returns: weird sampling duration.

.. zeek:id:: Reporter::get_weird_sampling_global_list
   :source-code: base/bif/reporter.bif.zeek 127 127

   :Type: :zeek:type:`function` () : :zeek:type:`string_set`

   Gets the weird sampling global list
   

   :returns: Current weird sampling global list

.. zeek:id:: Reporter::get_weird_sampling_rate
   :source-code: base/bif/reporter.bif.zeek 156 156

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Gets the current weird sampling rate.
   

   :returns: weird sampling rate.

.. zeek:id:: Reporter::get_weird_sampling_threshold
   :source-code: base/bif/reporter.bif.zeek 141 141

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Gets the current weird sampling threshold
   

   :returns: current weird sampling threshold.

.. zeek:id:: Reporter::get_weird_sampling_whitelist
   :source-code: base/bif/reporter.bif.zeek 113 113

   :Type: :zeek:type:`function` () : :zeek:type:`string_set`

   Gets the weird sampling whitelist
   

   :returns: Current weird sampling whitelist

.. zeek:id:: Reporter::info
   :source-code: base/bif/reporter.bif.zeek 25 25

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`bool`

   Generates an informational message.
   

   :msg: The informational message to report.
   

   :returns: Always true.
   
   .. zeek:see:: reporter_info

.. zeek:id:: Reporter::net_weird
   :source-code: base/bif/reporter.bif.zeek 71 71

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, addl: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`, source: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Generates a "net" weird.
   

   :name: the name of the weird.
   

   :returns: Always true.

.. zeek:id:: Reporter::set_weird_sampling_duration
   :source-code: base/bif/reporter.bif.zeek 179 179

   :Type: :zeek:type:`function` (weird_sampling_duration: :zeek:type:`interval`) : :zeek:type:`bool`

   Sets the current weird sampling duration. Please note that
   this will not delete already running timers.
   

   :weird_sampling_duration: New weird sampling duration.
   

   :returns: always returns True

.. zeek:id:: Reporter::set_weird_sampling_global_list
   :source-code: base/bif/reporter.bif.zeek 135 135

   :Type: :zeek:type:`function` (weird_sampling_global_list: :zeek:type:`string_set`) : :zeek:type:`bool`

   Sets the weird sampling global list
   

   :global_list: New weird sampling rate.
   

   :returns: Always true.

.. zeek:id:: Reporter::set_weird_sampling_rate
   :source-code: base/bif/reporter.bif.zeek 164 164

   :Type: :zeek:type:`function` (weird_sampling_rate: :zeek:type:`count`) : :zeek:type:`bool`

   Sets the weird sampling rate.
   

   :weird_sampling_rate: New weird sampling rate.
   

   :returns: Always returns true.

.. zeek:id:: Reporter::set_weird_sampling_threshold
   :source-code: base/bif/reporter.bif.zeek 149 149

   :Type: :zeek:type:`function` (weird_sampling_threshold: :zeek:type:`count`) : :zeek:type:`bool`

   Sets the current weird sampling threshold
   

   :threshold: New weird sampling threshold.
   

   :returns: Always returns true;

.. zeek:id:: Reporter::set_weird_sampling_whitelist
   :source-code: base/bif/reporter.bif.zeek 121 121

   :Type: :zeek:type:`function` (weird_sampling_whitelist: :zeek:type:`string_set`) : :zeek:type:`bool`

   Sets the weird sampling whitelist
   

   :whitelist: New weird sampling rate.
   

   :returns: Always true.

.. zeek:id:: Reporter::warning
   :source-code: base/bif/reporter.bif.zeek 35 35

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`bool`

   Generates a message that warns of a potential problem.
   

   :msg: The warning message to report.
   

   :returns: Always true.
   
   .. zeek:see:: reporter_warning


