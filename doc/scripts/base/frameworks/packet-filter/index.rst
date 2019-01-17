:orphan:

Package: base/frameworks/packet-filter
======================================

The packet filter framework supports how Bro sets its BPF capture filter.

:doc:`/scripts/base/frameworks/packet-filter/utils.bro`


:doc:`/scripts/base/frameworks/packet-filter/__load__.bro`


:doc:`/scripts/base/frameworks/packet-filter/main.bro`

   This script supports how Bro sets its BPF capture filter.  By default
   Bro sets a capture filter that allows all traffic.  If a filter
   is set on the command line, that filter takes precedence over the default
   open filter and all filters defined in Bro scripts with the
   :bro:id:`capture_filters` and :bro:id:`restrict_filters` variables.

:doc:`/scripts/base/frameworks/packet-filter/netstats.bro`

   This script reports on packet loss from the various packet sources.
   When Bro is reading input from trace files, this script will not
   report any packet loss statistics.

