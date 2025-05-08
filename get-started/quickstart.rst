.. _ZeekControl documentation: https://github.com/zeek/zeekctl
.. _FAQ: https://zeek.org/faq/

.. _quickstart:

=================
Quick Start Guide
=================

Zeek is a network traffic analyzer. Zeek works on most modern Unix-based
systems and requires no custom hardware. See :doc:`install` in order to
install from pre-built binary packages, or :doc:`building-from-source` in order
to build Zeek from source.

Zeek requires some network traffic in order to run. For this guide, we’ll use
an example ``http.pcap`` - this is a capture of HTTP network traffic. Later in
the guide, this traffic will be made via ``curl``.

TODO: Need to provide the http.pcap file.

Running Zeek
============

Open a terminal, find a clean directory, and run zeek on the ``http.pcap`` file
as follows:

   .. code-block:: console

     zeek -C -r http.pcap

Zeek should not produce any output, but it will create a few log files:

   .. code-block:: console

     conn.log
     http.log
     weird.log

The connection log, or conn.log, contains entries for each “connection” that
Zeek sees. The conn.log created has two entries. These are those entries,
where fields cut for brevity are represented with “...”:

   .. code-block:: console

     #fields ts      uid	…
     #types  time    string	…
     1736454354.671091       Cfuqgv31H35CiA9kYk	…
     1736454353.487971       Cjxhho3RkGqJKPRZK6	…

Now to find out more about both of these connections. Looking at the HTTP log
it also has two entries. Correlate these to the connection log entries from the
first two fields, namely the timestamp and unique identifier (uid). The
complete logs for these two requests are:

   .. code-block:: console

     #fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p trans_depth      method  host    uri     referrer        version user_agent      origin     request_body_len        response_body_len       status_code     status_msginfo_code        info_msg        tags    username        password        proxied orig_fuids orig_filenames  orig_mime_types resp_fuids      resp_filenames  resp_mime_types
     #types  time    string  addr    port    addr    port    count   string  string  string     string  string  string  string  count   count   count   string  count   string     set[enum]       string  string  set[string]     vector[string]  vector[string]     vector[string]  vector[string]  vector[string]  vector[string]
     1736454353.509713       Cjxhho3RkGqJKPRZK6      2603:6081:18f0:99e0:b522:7cab:b662:91a1    58952   2606:2800:21f:cb07:6820:80da:af6b:8b2c  80      1       GET     example.com        /       -       1.1     curl/8.7.1      -       0       1256    200OK      -       -       (empty) -       -       -       -       -       -       F6MJ811RP4HrQynO4d -       text/html
     1736454354.694917       Cfuqgv31H35CiA9kYk      2603:6081:18f0:99e0:b522:7cab:b662:91a1    58953   2606:2800:21f:cb07:6820:80da:af6b:8b2c  80      1       WEIRD   example.com        /       -       1.0     curl/8.7.1      -       0       357     501Not Implemented -       -       (empty) -       -       -       -       -       - FHiV4y2cB3ttkH0pE3       -       text/html

TODO: Formatting this. This could probably just be JSON, then remove fields.

The first entry in http.log has a UID corresponding to the second entry in
conn.log (TODO why are these out of order? does it matter?). That is a simple
``GET`` request to example.com. The second entry has the same UID as the first
entry in conn.log. The HTTP method was ``WEIRD``. For this case, Zeek will also
generate a separate log for some unexpected behavior (or "weirds"), like an
unknown HTTP method. You can find this in weird.log:

   .. code-block:: console

     #fields ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p name     addl    notice  peer    source
     #types  time    string  addr    port    addr    port    string  string  bool    string     string
     1736454354.694917       Cfuqgv31H35CiA9kYk      2603:6081:18f0:99e0:b522:7cab:b662:91a1    58953   2606:2800:21f:cb07:6820:80da:af6b:8b2c  80      unknown_HTTP_methodWEIRD   F       zeek    -

TODO: Same formatting thing as above

The UID for this entry is the same as the first entry in conn.log and the second
entry in http.log. Therefore, there were two HTTP requests, one with a ``GET``
request and one with a ``WEIRD`` request. The ``WEIRD`` request was rightfully
classified as a “weird” by Zeek.

More information on the various logs and what they report can be found in the
:doc:`../logs/index` section. More information on working with logs can be found in
the :doc:`../log-formats` section.

Scripting
=========

Zeek can also use its own scripting language in order to configure behavior and
react to events:

.. code-block:: zeek

     event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
         {
             print fmt("HTTP request: %s %s (%s->%s)", method, original_URI, c$id$orig_h, c$id$resp_h);
         }

This script defines an event that will run whenever Zeek sees an HTTP request.
You can run it through Zeek with the data from the pcap:

.. code-block:: console

     $ zeek weird-test.zeek -Cr http.pcap
     HTTP request: GET / (192.168.1.8->192.0.78.212)
     HTTP request: WEIRD / (192.168.1.8->192.0.78.212)

More information on how to use Zeek’s scripting language can be found in the
:doc:`../scripting/index` section.

Live Traffic
============

Zeek is often run on live traffic on a network, not just captured traffic.
Locally, you can provide Zeek with a network interface. Any traffic on that
interface will be analyzed in order to create logs. For example, you may run
Zeek on the ``en0`` network device (TODO: maybe link to a tutorial to figure out
how to get the correct device? Or an “any” device? Kubeshark has “any”)

.. code-block:: console

     $ zeek weird-test.zeek -i en0

Then, in another terminal, create the same two HTTP requests we saw earlier via
``curl``:

.. code-block:: console

     $ curl -X GET http://zeek.org
     $ curl -X WEIRD http://zeek.org

Zeek should output the same two lines we saw before. Furthermore, you can
analyze the http.log and weird.log to find that they contain entries for these
requests.

Managing Zeek
=============

Zeek comes packaged with ZeekControl (`zeekctl`) in order to operate and manage
more in-depth Zeek use cases.

TODO: Mention local.zeek here probably?

The same network device used in the Zeek command line can be used with
``zeekctl``. This will go in a configuration file. For the following example,
``$PREFIX`` will refer to the installation directory. This is likely
``/usr/local/zeek`` if built from source or ``/opt/zeek`` if installed from a
pre-built package.

First, update the configuration’s interface in ``$PREFIX/etc/node.cfg``. If
the device is ``en0``, that would look like:

.. code-block:: console

     [zeek]
     type=standalone
     host=localhost
     interface=en0

Run ``zeekctl`` in order to get into a new prompt:

.. code-block:: console

     $ zeekctl
     Hint: Run the zeekctl "deploy" command to get started.

     Welcome to ZeekControl 2.5.0-76

     Type "help" for help.

     [ZeekControl] >

Then run ``deploy`` to get started:

.. code-block:: console

     [ZeekControl] > deploy

In another terminal, run the same two curl commands from before:

.. code-block:: console

     $ curl -X GET http://zeek.org
     $ curl -X WEIRD http://zeek.org

Then return to the ZeekControl prompt and stop it:

.. code-block:: console

     [ZeekControl] > stop
     stopping zeek ...

And exit from ``zeekctl``:

.. code-block:: console

     [ZeekControl] > exit

The logs from ZeekControl will not appear in your current directory. Instead,
they will appear in ``$PREFIX/logs/current`` when running. Since the process was
stopped, they will appear in a directory with the current date within 
``$PREFIX/logs/`` - such as ``$PREFIX/logs/2025-01-01/``.

These logs are compressed as ``.log.gz`` files from gzip. You may decompress
these via ``gzip`` then read them, or use gzip’s packaged ``zcat`` command.
On Mac (TODO: zcat is different on Mac/Linux apparently), this may look like:

.. code-block:: console

     $ zcat < ~/.local/zeek/logs/2025-01-08/weird.11:03:38-11:03:43.log.gz
     <...>
     1736352218.157077       CFvENWVlkwVHhLL35       2603:6081:18f0:99e0:7da2:6b81:9a83:cb4e 57823   2606:2800:21f:cb07:6820:80da:af6b:8b2c   80      unknown_HTTP_method     WEIRD   F       zeek    -

The logs contain the ``WEIRD`` HTTP request.

More information on using ZeekControl can be found in the
`ZeekControl documentation`_. More information on setting up a cluster can be
found in the :doc:`cluster-setup` section.

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
* Join the Zeek community :slacklink:`Slack channel <>` or :discourselink:`forum <>`
  for interacting with fellow Zeekers and Zeek core developers.
* Track Zeek code releases by reading the "Release Notes" for each release.
  The "Get Zeek" web page points to this file for each new version of Zeek.
  These notes appear as the file NEWS, which summarizes the most important
  changes in the new version. These same notes are attached to the release
  page on GitHub for each release. For details on each change, see the
  separate CHANGES file, also accompanying each release.
