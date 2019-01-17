:orphan:

Package: base/protocols/conn
============================

Support for connection (TCP, UDP, or ICMP) analysis.

:doc:`/scripts/base/protocols/conn/__load__.bro`


:doc:`/scripts/base/protocols/conn/main.bro`

   This script manages the tracking/logging of general information regarding
   TCP, UDP, and ICMP traffic.  For UDP and ICMP, "connections" are to
   be interpreted using flow semantics (sequence of packets from a source
   host/port to a destination host/port).  Further, ICMP "ports" are to
   be interpreted as the source port meaning the ICMP message type and
   the destination port being the ICMP message code.

:doc:`/scripts/base/protocols/conn/contents.bro`

   This script can be used to extract either the originator's data or the 
   responders data or both.  By default nothing is extracted, and in order 
   to actually extract data the ``c$extract_orig`` and/or the
   ``c$extract_resp`` variable must be set to ``T``.  One way to achieve this
   would be to handle the :bro:id:`connection_established` event elsewhere
   and set the ``extract_orig`` and ``extract_resp`` options there.
   However, there may be trouble with the timing due to event queue delay.
   
   .. note::
   
      This script does not work well in a cluster context unless it has a
      remotely mounted disk to write the content files to.

:doc:`/scripts/base/protocols/conn/inactivity.bro`

   Adjust the inactivity timeouts for interactive services which could
   very possibly have long delays between packets.

:doc:`/scripts/base/protocols/conn/polling.bro`

   Implements a generic way to poll connections looking for certain features
   (e.g. monitor bytes transferred).  The specific feature of a connection
   to look for, the polling interval, and the code to execute if the feature
   is found are all controlled by user-defined callback functions.

:doc:`/scripts/base/protocols/conn/thresholds.bro`

   Implements a generic API to throw events when a connection crosses a
   fixed threshold of bytes or packets.

