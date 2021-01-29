.. _ZeekControl documentation: https://github.com/zeek/zeekctl
.. _FAQ: https://zeek.org/faq/

.. _quickstart:

=================
Quick Start Guide
=================

Zeek works on most modern Unix-based systems and requires no custom hardware.
It can be downloaded in either pre-built binary package or source code forms.
See :ref:`installing-zeek` for instructions on how to install Zeek.

In the examples below, ``$PREFIX`` is used to reference the Zeek installation
root directory, which by default is :file:`/usr/local/zeek` if you install from
source and :file:`/opt/zeek` if you install from the pre-built binary packages.

Managing Zeek with ZeekControl
==============================

ZeekControl is an interactive shell for easily operating/managing Zeek
installations on a single system or even across multiple systems in a
traffic-monitoring cluster. This section explains how to use ZeekControl to
manage a stand-alone Zeek installation. For a complete reference on
ZeekControl, see the `ZeekControl documentation`_.
For instructions on how to configure a Zeek cluster, see the :doc:`clusters`
documentation.

.. note:: Using the standalone / single process mode of Zeek is not suitable
          for setups with significant amounts of traffic. In these cases one
          will almost certainly want to make use of a Zeek cluster,
          even on a single system.

A Minimal Starting Configuration
--------------------------------

These are the basic configuration changes to make for a minimal ZeekControl
installation that will manage a single (standalone) Zeek instance on the
``localhost``:

1. [Required]: In :samp:`{$PREFIX}/etc/node.cfg`, set the right interface to monitor.

   For example:

   .. code-block:: console

     vi $PREFIX/etc/node.cfg

   ::

     [zeek]
     type=standalone
     host=localhost
     interface=eth0   # change this according to your listening interface in ifconfig

2. [Optional but recommended]: In :samp:`{$PREFIX}/etc/networks.cfg`, comment
   out the default settings and add the networks that Zeek will consider local
   to the monitored environment.

3. [Optional]: In :samp:`{$PREFIX}/etc/zeekctl.cfg`, change the ``MailTo``
   email address to a desired recipient and the ``LogRotationInterval`` to
   a desired log archival frequency.

Now start the ZeekControl shell like:

.. code-block:: console

  zeekctl

Since this is the first-time use of the shell, perform an initial installation
of the ZeekControl configuration:

.. code-block:: console

  [ZeekControl] > install

Then start up a Zeek instance:

.. code-block:: console

  [ZeekControl] > start

There is another ZeekControl command, ``deploy``, that combines the above two
steps and can be run after any changes to Zeek policy scripts or the
ZeekControl configuration. Note that the ``check`` command is available to
validate a modified configuration before installing it.

.. code-block:: console

  [ZeekControl] > deploy

If there are errors while trying to start the Zeek instance, you can view the
details with the ``diag`` command.  If started successfully, the Zeek instance
will begin analyzing traffic according to a default policy and output the
results in :samp:`{$PREFIX}/logs/current` directory.

.. note::

  The user starting ZeekControl needs permission to capture network traffic. If
  you are not root, you may need to grant further privileges to the account
  you’re using; see the FAQ_. Also, if it looks like Zeek is not seeing any
  traffic, check out the FAQ_ entry on checksum offloading.

You can leave it running for now, but to stop this Zeek instance you would do:

.. code-block:: console

  [ZeekControl] > stop

Once Zeek is stopped, the log files in the :samp:`{$PREFIX}/logs/current`
directory are compressed and moved into the current day named folder inside the
:samp:`{$PREFIX}/logs` directory.

Browsing Log Files
------------------

By default, logs are written out in human-readable (ASCII) format and data is
organized into columns (tab-delimited). Logs that are part of the current
rotation interval are accumulated in :samp:`{$PREFIX}/logs/current/` (if Zeek
is not running, the directory will be empty). For example, the :file:`http.log`
contains the results of Zeek HTTP protocol analysis. Here are the first few
columns of :file:`http.log`::

  # ts          uid          orig_h        orig_p  resp_h         resp_p
  1311627961.8  HSH4uV8KVJg  192.168.1.100 52303   192.150.187.43 80

Logs that deal with analysis of a network protocol will often start like this:
a timestamp, a unique connection identifier (UID), and a connection 4-tuple
(originator host/port and responder host/port). The UID can be used to identify
and correlate all logged activity (possibly across multiple log files)
associated with a given connection 4-tuple over its lifetime.

The remaining columns of protocol-specific logs then detail the
protocol-dependent activity that’s occurring. E.g. :file:`http.log`’s next few
columns (shortened for brevity) show a request to the root of Zeek website::

  # method   host         uri  referrer  user_agent
  GET        zeek.org  /    -         <...>Chrome/12.0.742.122<...>

Apart from the conventional network protocol specific log files, Zeek also
generates other important log files based on the network traffic statistics,
interesting activity captured in the traffic, and detection focused log files.
Some logs that are worth explicit mention:

* :file:`conn.log`

  Contains an entry for every connection seen on the wire, with basic properties
  such as time and duration, originator and responder IP addresses, services and
  ports, payload size, and much more. This log provides a comprehensive record of
  the network’s activity.

* :file:`notice.log`

  Identifies specific activity that Zeek recognizes as potentially interesting,
  odd, or bad. In Zeek-speak, such activity is called a “notice”.

* :file:`known_services.log`

  This log file contains the services detected on the local network and are known
  to be actively used by the clients on the network. It helps in enumerating what
  all services are observed on a local network and if they all are intentional
  and known to the network administrator.

* :file:`weird.log`

  Contains unusual or exceptional activity that can indicate malformed
  connections, traffic that doesn’t conform to a particular protocol,
  malfunctioning or misconfigured hardware/services, or even an attacker
  attempting to avoid/confuse a sensor.

By default, ZeekControl regularly takes all the logs from
:samp:`{$PREFIX}/logs/current` and archives/compresses them to a directory
named by date, e.g.  :samp:`{$PREFIX}/logs/2021-01-01`. The frequency at which
this is done can be configured via the ``LogRotationInterval`` option in
:samp:`{$PREFIX}/etc/zeekctl.cfg`. The default is every hour.

Filesystem Walkthrough
----------------------

When Zeek is installed on a system, it creates various directories under the
default installation path :file:`/usr/local/zeek/` or :file:`/opt/zeek/`. It is
useful to know the basic filesystem layout and which directories contain what
information.  Below is the basic Zeek filesystem layout::

  $PREFIX/ (e.g. /opt/zeek/ or /usr/local/zeek/)
  |_ bin/
  |_ etc/
  |_ include/
  |_ lib/
  |_ logs/
  |_ share/
  |_ spool/

Some subdirectories worth more explanation are:

* :samp:`{$PREFIX}/bin/`

  This directory contains all the binaries that get installed as part of Zeek
  installation. Few important ones you should know about are:

  * :program:`zeek`

    Binary to use when running Zeek as a command line utility. More information
    on using the binary follows in the next section.

  * :program:`zeek-cut`

    Extracts columns from zeek logs (non-JSON), comes handy for log analysis,
    and also converts Unix epoch time to human readable format.

  * :program:`zeekctl`

    Mainly used as a Zeek cluster management tool, it’s an interactive shell to
    easily operate/manage Zeek installations.

* :samp:`{$PREFIX}/etc/`

  This directory contains the important configuration files that need to be
  modified for the minimal starting configuration as well as for configuring an
  advanced Zeek cluster installation. This is one of the important directories
  from the user perspective, and one should be familiar with the files in
  contains:

  * :file:`networks.cfg`

    Define your local networks here. Zeek analytics are network aware and it is
    recommended to use this file to define your local networks for efficient
    and correct analysis of the network traffic.

  * :file:`node.cfg`

    Configure a stand-alone node or a Zeek cluster configuration by defining
    various node types and their corresponding settings. It has examples
    defined for both stand-alone and clustered configurations for the user to
    use.

  * :file:`zeekctl.cfg`

    Configuration file for ZeekControl management. It contains the settings of
    default logs directory, log rotation time interval and email configuration.

* :samp:`{$PREFIX}/logs/`

  As the name suggests it is the default logs directory where Zeek stores the
  rotated logs from the current directory:

  * :file:`current`

    It is a symlink to the spool directory that is defined in the zeekctl.cfg
    configuration file. It contains the active log files that Zeek currently
    writes to when running via ZeekControl.

* :samp:`{$PREFIX}/share/`

  This is the directory containing all the Zeek scripts that are shipped with
  Zeek, which are highly customizable to support traffic analysis for your
  specific environment. For the people who are interested in learning more
  about Zeek scripts and different frameworks, this is a great place to start.
  The important sub-directories under share are:

  * :file:`zeek/base/`

    It contains base scripts that are always loaded by Zeek (unless the ``-b``
    command line option is supplied). These files should never be edited
    directly as changes will be lost when upgrading to newer versions of Zeek.
    Base scripts  deal either with collecting basic/useful state about network
    activities or providing frameworks/utilities that extend Zeek’s
    functionality without any performance cost.

  * :file:`zeek/policy/`

    Additional policy scripts that zeek ships with. Scripts under the
    :file:`policy/` directory may be more situational or costly, and so users
    must explicitly choose if they want to load them. By default, Zeek loads a
    few of the most useful policy scripts, as enabled via the local.zeek file
    in the site directory. These scripts should likewise never be modified.

  * :file:`zeek/site/`

    It is the directory where local site-specific files/scripts can be put
    without fear of being clobbered later (with Zeek upgrades). The main entry
    point for the default analysis configuration of a Zeek instance managed by
    ZeekControl is the :samp:`{$PREFIX}/share/zeek/site/local.zeek` script,
    which can be used to load additional custom or policy scripts.

Zeek as a Command-Line Utility
==============================

If you prefer not to use ZeekControl (e.g., you don’t need its automation and
management features), here’s how to directly control Zeek for your analysis
activities from the command line for both live traffic and offline working from
traces.

Monitoring Live Traffic
-----------------------

Analyzing live traffic from an interface is simple:

.. code-block:: console

   zeek -i en0 <list of scripts to load>


``en0`` should be replaced by the interface on which you want to monitor the
traffic. The standard base scripts will be loaded and enabled by default. A
list of additional scripts can be provided in the command as indicated
above by ``<list of scripts to load>``.  Any such scripts supplied as
space-separated files or paths will be loaded by Zeek in addition to the
standard base scripts.

Zeek will output log files into the current working directory.

.. note:: The FAQ_ entries about
   capturing as an unprivileged user and checksum offloading are
   particularly relevant at this point.

Reading Packet Capture (pcap) Files
-----------------------------------

When you want to do offline analysis of already captured pcap files, Zeek is a
very handy tool to analyze the pcap and gives a high level holistic view of the
traffic captured in the pcap.

If you want to capture packets from an interface and write them to a file to
later analyze it with Zeek, then it can be done like this:

.. code-block:: console

  sudo tcpdump -i en0 -s 0 -w mypackets.trace

Where ``en0`` should be replaced by the correct interface for your system, for
example as shown by the :program:`ifconfig` command. (The ``-s 0`` argument
tells it to capture whole packets; in cases where it’s not supported use ``-s
65535`` instead).

After capturing traffic for a while, kill the tcpdump (with *ctrl-c*), and tell
Zeek to perform all the default analysis on the capture:

.. code-block:: console

  zeek -r mypackets.trace

Zeek will output log files into the working directory.

If no logs are generated for a pcap, try to run the pcap with ``-C`` to tell
Zeek to ignore invalid IP Checksums:

.. code-block:: console

  zeek –C –r mypackets.trace

If you are interested in more detection, you can load the :file:`local.zeek`
script that is included as a suggested configuration:

.. code-block:: console

  zeek -r mypackets.trace local

If you want to run a custom or an extra script (assuming it’s in the default
search path, more on this in the next section) to detect any particular
behavior in the pcap, run Zeek with following command:

.. code-block:: console

  zeek –r mypackets.trace my-script.zeek

Telling Zeek Which Scripts to Load
----------------------------------

A command-line invocation of Zeek typically looks like:

.. code-block:: console

  zeek <options> <scripts...>

Where the last arguments are the specific policy scripts that this Zeek
instance will load. These arguments don’t have to include the :file:`.zeek`
file extension, and if the corresponding script resides in the default search
path, then it requires no path qualification. The following directories are
included in the default search path for Zeek scripts::

  ./
  <prefix>/share/zeek/
  <prefix>/share/zeek/policy/
  <prefix>/share/zeek/site/

These prefix paths can be used to load scripts like this:

.. code-block:: console

  zeek -r mypackets.trace frameworks/files/extract-all-files

This will load the
:samp:`{$PREFIX}/share/zeek/policy/frameworks/files/extract-all-files.zeek`
script which will cause Zeek to extract all of the files it discovers in the
pcap.

.. note::

  If one wants Zeek to be able to load scripts that live outside the default
  directories in Zeek’s installation root, the full path to the file(s) must be
  provided. See the default search path by running ``zeek --help`` and look at
  :envvar:`ZEEKPATH`. You can also extend the search path by setting the
  environment variable :envvar:`ZEEKPATH` to additional directories (note that
  you will need to repeat the original path when setting :envvar:`ZEEKPATH` as
  otherwise Zeek will not find it standard scripts.)

If you take a look inside a Zeek script, you might notice the ``@load``
directive in the Zeek language to declare dependence on other scripts. This
directive is similar to the ``#include`` of C/C++, except the semantics are,
“load this script if it hasn’t already been loaded.”

Further, a directory of scripts can also be specified as an argument to be
loaded as a “package” if the directory contains a :file:`__load__.zeek` script
that defines the scripts that are part of the package (note the double
underscore (``_``) characters on each end).

For example:

.. code-block:: console

  zeek -r mypackets.trace detect-traceroute

This will load the scripts inside the directory “detect-traceroute”, which is
under :samp:`{$PREFIX}/share/zeek/policy/misc/detect-traceroute` and contains a
:file:`__load__.zeek` script telling zeek which scripts to load under that
directory to run against the pcap.

Local site customization
------------------------

There is one script that is installed which is considered “local site
customization” and is not overwritten when upgrades take place. To use the
site-specific :file:`local.zeek` script, just add it to the command-line (can
also be loaded through scripts with ``@load``; ZeekControl loads it
automatically):

.. code-block:: console

  zeek -i en0 local

With a fresh installation, this causes Zeek to load a script that prints a
warning about lacking the :zeek:see:`Site::local_nets` variable being
configured. You can supply this information in the :file:`local.zeek` file or
at the command line like this (supply your “local” subnets in place of the
example subnets):

.. code-block:: console

  zeek -r mypackets.trace local -e "Site::local_nets += { 1.2.3.0/24, 5.6.7.0/24 }"

When running with ZeekControl, this value is set by configuring the
:file:`networks.cfg` file.  Note the example also shows how you can execute
script code without it being in a :file:`.zeek` file.

Running Zeek Without Installing
-------------------------------

For developers that wish to run Zeek directly from the :file:`build/` directory
(i.e., without performing ``make install``), they will have to first adjust
:envvar:`ZEEKPATH` to look for scripts and additional files inside the build
directory. Sourcing either :file:`build/zeek-path-dev.sh` or
:file:`build/zeek-path-dev.csh` as appropriate for the current shell
accomplishes this and also augments your :envvar:`PATH` so you can use the Zeek
binary directly:

.. code-block:: console

  ./configure
  make
  source build/zeek-path-dev.sh
  zeek <options>

Next Steps
==========

By this point, we’ve covered how to set up the most basic Zeek instance,
browsing log files and a basic filesystem layout. Here’s some suggestions on
what to explore next:

* Simply continue reading further into this documentation to find out more
  about the contents of Zeek log files and how to write custom Zeek scripts.
* Look at the scripts in :samp:`{$PREFIX}/share/zeek/policy`
  for further ones you may want to load; you can browse their documentation at
  the :ref:`overview of script packages <script-packages>`.
* Reading the code of scripts that ship with Zeek is also a great way to gain
  further understanding of the language and how scripts tend to be structured.
* Review the FAQ_.
* Join the Zeek community Slack channel for interacting with the fellow Zeekers
  and Zeek core developers.
