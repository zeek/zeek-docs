.. _histogram_quantile(): https://prometheus.io/docs/prometheus/latest/querying/functions/#histogram_quantile
.. _Prometheus Getting Started Guide: https://prometheus.io/docs/prometheus/latest/getting_started/
.. _CAF: https://github.com/actor-framework/actor-framework

.. _framework-telemetry:

===================
Telemetry Framework
===================

The telemetry framework can be used to record metrics. This framework
is fairly Prometheus inspired, and supports the same metric types with
the exception of Summary.

The actual implementation of the metrics and their registry is provided
by :ref:`Broker <broker-framework>` and internally CAF_.

This document mostly provides usage examples. Head to the :zeek:see:`Telemetry`
API documentation for more details.

Metric Types
============

The following metric types are supported.

  Counter
    Continuously increasing, resets on process restart.
    Examples are number of log writes since process start, ``process_seconds``,
    packets processed.

  Gauge
    Can increase and decrease.
    Examples are table sizes or :zeek:see:`val_footprint` of values with process
    lifetime, temperature, memory usage.

  Histogram
    Pre-configured buckets of observations.
    Examples are connection durations, delays, request durations for which
    the expected range is known.


Examples
========

Counting Log Writes per Stream
------------------------------

In combination with the :zeek:see:`Log::log_stream_policy` hook, it is
straight forward to record :zeek:see:`Log::write` invocations over the
dimension of the :zeek:see:`Log::ID` value. In other words, a stringified
version of the :zeek:see:`Log::ID` is used as a label value.

This section shows three different approaches. Which approach is most
applicable depends on the metrics being recorded, the expected frequency
and the script level performance overhead.

Assuming Zeek was started with ``BROKER_METRICS_PORT`` being set in the
environment, querying the Prometheus endpoint using ``curl`` provides the
following metrics data for each of the approaches.

.. code-block::

   $ curl -s localhost:4242/metrics | grep log_writes
   # HELP zeek_log_writes_total Number of log writes per stream
   # TYPE zeek_log_writes_total counter
   zeek_log_writes_total{endpoint="zeek",log_id="packetfilter_log"} 1.000000 1658924926624
   zeek_log_writes_total{endpoint="zeek",log_id="loadedscripts_log"} 477.000000 1658924926624
   zeek_log_writes_total{endpoint="zeek",log_id="stats_log"} 1.000000 1658924926624
   zeek_log_writes_total{endpoint="zeek",log_id="dns_log"} 200.000000 1658924926624
   zeek_log_writes_total{endpoint="zeek",log_id="ssl_log"} 9.000000 1658924926624
   zeek_log_writes_total{endpoint="zeek",log_id="conn_log"} 215.000000 1658924926624
   zeek_log_writes_total{endpoint="zeek",log_id="captureloss_log"} 1.000000 1658924926624


Immediate
^^^^^^^^^

.. literalinclude:: telemetry/log-writes-immediate.zeek
   :caption: log-writes-immediate.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

With a few lines of Zeek scripting code, these new metrics are now available
for scraping by a Prometheus server.

Cached
^^^^^^

For cases where creating the label values vector and invoking the
:zeek:see:`Telemetry::counter_family_inc` methods cause too much
overhead, the counter instance can also be cached in a lookup table.
The counters can then be used with :zeek:see:`Telemetry::counter_inc`
directly.

.. literalinclude:: telemetry/log-writes-cached.zeek
   :caption: log-writes-cached.zeek
   :language: zeek
   :linenos:
   :tab-width: 4


For metrics without labels, the metric instances can also be set as global
variables directly. The following example counts the number of http requests

.. literalinclude:: telemetry/global-http-counter.zeek
   :caption: global-http-counter.zeek
   :language: zeek
   :linenos:
   :tab-width: 4


Sync
^^^^
In case where the scripting overhead for this approach is too high, the
individual writes (or events) can be tracked in a table which is then
synchronized / mirrored during execution of the :zeek:see:`Telemetry::sync`
hook.

.. literalinclude:: telemetry/log-writes-sync.zeek
   :caption: log-writes-sync.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

For the use-case of tracking log writes, this is unlikely to be required,
but for high frequency events that otherwise have a very low-overhead it's a
valuable approach to keep script execution overhead low. Note, metrics will
be stale up to the next :zeek:see:`Telemetry::sync_interval`.


Table sizes
-----------

It can be useful to expose the size of state holding tables as metrics.
As table sizes may increase and decrease, a :zeek:see:`Telemetry::Gauge`
is used.

The following example tracks the size of the Tunnel::active table and
its footprint. Note how no labels are used in this case.

.. literalinclude:: telemetry/table-size-tracking.zeek
   :caption: log-writes-sync.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

Example representation of these metrics when querying the Prometheus endpoint:

.. code-block::

   $ curl -s localhost:4243/metrics | grep tunnel
   # HELP zeek_monitored_tunnels_active_footprint Footprint of the Tunnel::active table
   # TYPE zeek_monitored_tunnels_active_footprint gauge
   zeek_monitored_tunnels_active_footprint{endpoint="zeek"} 324.000000 1658929821941
   # HELP zeek_monitored_tunnels_active Number of currently active tunnels as tracked in Tunnel::active
   # TYPE zeek_monitored_tunnels_active gauge
   zeek_monitored_tunnels_active{endpoint="zeek"} 12.000000 1658929821941

Connection Durations as Histogram
---------------------------------

To track the distribution of certain measurements, a :zeek:see:`Telemetry::Histogram`
can be used. The histogram's buckets have to be preconfigured.

Below example observes the duration of each connection that Zeek has
monitored.

.. literalinclude:: telemetry/connection-durations.zeek
   :caption: connection-durations.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

Due to the way Prometheus represents histograms and the fact that durations
are broken down by protocol and service, the resulting query is rather verbose
in output:

.. code-block::

   $ curl -s localhost:4242/metrics | grep monitored_connection_duration
   # HELP zeek_monitored_connection_duration_seconds Duration of monitored connections
   # TYPE zeek_monitored_connection_duration_seconds histogram
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="0.100000"} 970.000000 1658931613557
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="1.000000"} 998.000000 1658931613557
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="10.000000"} 1067.000000 1658931613557
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="30.000000"} 1108.000000 1658931613557
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="60.000000"} 1109.000000 1658931613557
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="udp",service="dns",le="+Inf"} 1109.000000 1658931613557
   zeek_monitored_connection_duration_seconds_sum{endpoint="zeek",proto="udp",service="dns"} 1263.085691 1658931613557
   zeek_monitored_connection_duration_seconds_count{endpoint="zeek",proto="udp",service="dns"} 1109.000000 1658931613557
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="0.100000"} 16.000000 1658931613557
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="1.000000"} 54.000000 1658931613557
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="10.000000"} 56.000000 1658931613557
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="30.000000"} 57.000000 1658931613557
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="60.000000"} 57.000000 1658931613557
   zeek_monitored_connection_duration_seconds_bucket{endpoint="zeek",proto="tcp",service="http",le="+Inf"} 57.000000 1658931613557


To work with histogram data, Prometheus provides specialized query functions.
For example `histogram_quantile()`_.

Note, using the ``conn.log`` and post-processing a proper histogram of
connection durations can be calculated and should possibly be preferred
depending on the use-case. The above is mostly meant for demonstration
purposes. Histograms may be primarily interesting for Zeek operational
metrics such as processing or queueing delays, response times to external
systems, etc.


Exporting the Zeek Version
--------------------------

A common pattern in the Prometheus ecosystem is to expose the version
information of the running process as gauge metric with a value of 1.

The following example does just that with a Zeek script:

.. literalinclude:: telemetry/version.zeek
   :caption: version.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

This is exposed in Prometheus format as follows:

.. code-block::

   $ curl -s localhost:4242/metrics | grep version
   # HELP zeek_version_info The Zeek version
   # TYPE zeek_version_info gauge
   zeek_version_info{beta="false",commit="289",debug="true",endpoint="zeek",major="5",minor="1",patch="0",version_number="50100",version_string="5.1.0-dev.289-debug"} 1.000000 1658936589580


Export
======

Zeek Log
--------

The metrics created using the telemetry module can be exported as
telemetry.log and telemetry_histogram.log by loading the policy
script ``frameworks/telemetry/log`` on the command line, or via
``local.zeek``.

The logs are documented through the :zeek:see:`Telemetry::Info`
and :zeek:see:`Telemetry::HistogramInfo` records, respectively.

Native Prometheus Export
------------------------

To enable the Prometheus endpoint for a Zeek process, set the
``BROKER_METRICS_PORT`` variable in its environment. As shown with
the ``curl`` examples in the previous section, a Prometheus server
can now be configured to scrape this Zeek process directly. See
also the `Prometheus Getting Started Guide`_.

In a cluster setup there are two possibilities. Either configure a
unique ``BROKER_METRICS_PORT`` and ``BROKER_ENDPOINT_NAME`` for each of
the Zeek processes and configure the Prometheus server to scrape each
of these endpoints.
Alternatively, set ``BROKER_METRICS_IMPORT_TOPICS`` and ``BROKER_METRICS_EXPORT_TOPIC``
environment variables to have a single process, presumably the Zeek manager,
import all metrics from other Zeek processes. Only set ``BROKER_METRICS_PORT``
for the Zeek manager and configure the Prometheus server to scrape only
the manager.
