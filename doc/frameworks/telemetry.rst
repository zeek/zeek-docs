.. _histogram_quantile(): https://prometheus.io/docs/prometheus/latest/querying/functions/#histogram_quantile
.. _Prometheus Getting Started Guide: https://prometheus.io/docs/prometheus/latest/getting_started/
.. _Prometheus Metric Types: https://prometheus.io/docs/concepts/metric_types/
.. _CAF: https://github.com/actor-framework/actor-framework

.. _framework-telemetry:

===================
Telemetry Framework
===================

The telemetry framework can be used to record metrics. Such metrics can either
revolve around Zeek's operational behavior, or describe characteristics of the
monitored traffic.

The telemetry framework is fairly Prometheus inspired. It supports the same
metric types as most Prometheus client libraries with the exception of the
Summary type.

The actual implementation of the metrics and the registry is provided
by :ref:`Broker <broker-framework>` and internally CAF_.

This document outlines usage examples. Head to the :zeek:see:`Telemetry`
API documentation for more details.

Metric Types
============

The following metric types are supported.

  Counter
    Continuously increasing, resets on process restart.
    Examples for counters are number of log writes since process start,
    packets processed, or ``process_seconds`` representing CPU usage.

  Gauge
    Gauge metric can increase and decrease.
    Examples are table sizes or :zeek:see:`val_footprint` of Zeek script
    values over the lifetime of the process. Temperature or memory usage
    are other examples.

  Histogram
    Pre-configured buckets of observations.
    Examples for histograms are connection durations, delays, transfer
    sizes. Generally, it is useful to know the expected range and distribution
    as the histogram's buckets are pre-configured.


A good reference to consult for more details is the official `Prometheus Metric Types`_ documentation.
The next section provides examples using each of these types.


Examples
========

Counting Log Writes per Stream
------------------------------

In combination with the :zeek:see:`Log::log_stream_policy` hook, it is
straight forward to record :zeek:see:`Log::write` invocations over the
dimension of the :zeek:see:`Log::ID` value.

This section shows three different approaches. Which approach is most
applicable depends mostly on the expected script layer performance overhead
for updating the metric.
For example, calling :zeek:see:`Telemetry::counter_with` and
:zeek:see:`Telemetry::counter_inc` within a handler of a high-frequency
event may be prohibitive, while for a low-frequency event it's unlikely
to be performance impacting.

Assuming Zeek was started with ``BROKER_METRICS_PORT=4242`` being set in the
environment, querying the Prometheus endpoint using ``curl`` provides the
following metrics data for each of the three approaches.

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

The following example creates a global counter family object and uses
the :zeek:see:`Telemetry::counter_family_inc` helper to increment the
counter metric associated with a string representation of the :zeek:see:`Log::ID`
value.


.. literalinclude:: telemetry/log-writes-immediate.zeek
   :caption: log-writes-immediate.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

With a few lines of scripting code, Zeek now track log writes per stream
ready to be scraped by a Prometheus server.


Cached
^^^^^^

For cases where creating the label value (stringification, :zeek:see:`gsub` and :zeek:see:`to_lower`)
and instantiating the label vector as well as invoking the
:zeek:see:`Telemetry::counter_family_inc` methods cause too much
performance overhead, the counter instances can also be cached in a lookup table.
The counters can then be incremented with :zeek:see:`Telemetry::counter_inc`
directly.

.. literalinclude:: telemetry/log-writes-cached.zeek
   :caption: log-writes-cached.zeek
   :language: zeek
   :linenos:
   :tab-width: 4


For metrics without labels, the metric instances can also be *cached* as global
variables directly. The following example counts the number of http requests.

.. literalinclude:: telemetry/global-http-counter.zeek
   :caption: global-http-counter.zeek
   :language: zeek
   :linenos:
   :tab-width: 4


Sync
^^^^

In case where the scripting overhead of this approach is still too high, the
individual writes (or events) can be tracked in a table and then
synchronized / mirrored during execution of the :zeek:see:`Telemetry::sync`
hook.

.. literalinclude:: telemetry/log-writes-sync.zeek
   :caption: log-writes-sync.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

For the use-case of tracking log writes, this is unlikely to be required, but
for updating metrics within high frequency events that otherwise have very
low processing overhead it's a valuable approach. Note, metrics will be stale
up to the next :zeek:see:`Telemetry::sync_interval` using this method.


Table sizes
-----------

It can be useful to expose the size of state holding tables as metrics.
As table sizes may increase and decrease, a :zeek:see:`Telemetry::Gauge`
is used for this purpose.

The following example records the size of the :zeek:see:`Tunnel::active` table
and its footprint with two gauges. The gauges are updated during the
:zeek:see:`Telemetry::sync` hook. Note, there are no labels in use, both
gauge instances are simple globals.

.. literalinclude:: telemetry/table-size-tracking.zeek
   :caption: log-writes-sync.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

Example representation of these metrics when querying the Prometheus endpoint:

.. code-block::

   $ curl -s localhost:4242/metrics | grep tunnel
   # HELP zeek_monitored_tunnels_active_footprint Footprint of the Tunnel::active table
   # TYPE zeek_monitored_tunnels_active_footprint gauge
   zeek_monitored_tunnels_active_footprint{endpoint="zeek"} 324.000000 1658929821941
   # HELP zeek_monitored_tunnels_active Number of currently active tunnels as tracked in Tunnel::active
   # TYPE zeek_monitored_tunnels_active gauge
   zeek_monitored_tunnels_active{endpoint="zeek"} 12.000000 1658929821941


Instead of tracking footprints per variable, :zeek:see:`global_container_footprints`,
could be leveraged to track all global containers at once, using the variable
name as label.

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
are broken down by protocol and service in the given example, the resulting
is rather verbose.

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

Note, when using data from `conn.log` and post-processing, a proper
histogram of connection durations can be calculated and possibly preferred.
The above example is meant for demonstration purposes. Histograms may be
primarily be useful for Zeek operational metrics such as processing times
or queueing delays, response times to external systems, etc.


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


Note, the `zeek_version_info` gauge is created by default in
:doc:`/scripts/base/frameworks/telemetry/main.zeek`. There is no need
to add above snippet to your site.

Metrics Export
==============

Cluster Considerations
----------------------

In a Zeek cluster, every node has its own metric registry independent
of the other nodes.

As noted below in the Prometheus section, the Broker subsystem can be configured
such that metrics from all nodes are imported to a single node for exposure
via the Prometheus HTTP endpoint. Concretely, the `manager` process can be
configured to import metrics from workers, proxies and loggers.

No aggregation of metrics happens during the import process. Rather, the centralized
metrics receive an additional "endpoint" label that can be used to identify
the originating node.

The :zeek:see:`Telemetry::collect_metrics` and :zeek:see:`Telemetry::collect_histogram_metrics`
functions only return node local metrics. A node importing metrics will not
expose metrics from other nodes to the scripting layer.

When configuring the `telemetry.log` and `telemetry_histogram.log`, each node
in a cluster is logging its own metrics. The logs contain a `peer` field that
can be used to determine from which node the metrics originated from.


Zeek Log
--------

The metrics created using the telemetry module can be exported as
`telemetry.log` and `telemetry_histogram.log` by loading the policy
script ``frameworks/telemetry/log`` on the command line, or via
``local.zeek``.

The logs are documented through the :zeek:see:`Telemetry::Info`
and :zeek:see:`Telemetry::HistogramInfo` records, respectively.

By default, only metrics with the `prefix` (namespace) ``zeek`` and ``process``
are included in above logs. If you add new metrics with your own prefix
and expect these to be included, redefine the
:zeek:see:`Telemetry::log_prefixes` option::

    @load frameworks/telemetry/log

    redef Telemetry::log_prefixes += { "my_prefix" };


Native Prometheus Export
------------------------

When running a cluster of Zeek processes, the manager process can be configured
to run a HTTP server on port 9911/tcp for Prometheus exposition by loading the
following policy script::

    @load frameworks/telemetry/prometheus

This script instructs the manager process to import all metrics from other
Zeek processes via Broker and configures other nodes to regularly export their metrics.
Querying the manager's Prometheus endpoint (``curl http://manager-ip:9911/metrics``)
then yields its own metrics as well as metrics from all other processes in the
Zeek cluster. The ``endpoint`` label on the metrics can be used to differentiate
the originator.

.. note::

   .. versionchanged:: 6.0

   This script was previously loaded by default. Due to adding extra processing
   overhead to the manager process even if Prometheus is not used, this is not
   the default anymore. Future improvements may allow to load the script by
   default again.

As shown with the ``curl`` examples in the previous section, a Prometheus
server can be configured to scrape the Zeek manager process directly.
See also the `Prometheus Getting Started Guide`_.

The ``scripts/policy/frameworks/telemetry/prometheus.zeek`` script sets
:zeek:see:`Broker::metrics_port`, :zeek:see:`Broker::metrics_import_topics`,
:zeek:see:`Broker::metrics_export_topic` and :zeek:see:`Broker::metrics_export_endpoint_name`
appropriately.

.. above file isn't included in the docs as it's not loaded in the doc generation, can not use :doc:


If this configuration isn't right for your environment, there's
the possibility to redefine the options in ``local.zeek`` to something more
suitable. For example, the following snippet opens an individual Prometheus
port for each Zeek process (relative to the port used in ``cluster-layout.zeek``)
and disables the export and import of metrics::


    @load base/frameworks/cluster

    global my_node = Cluster::nodes[Cluster::node];
    global my_metrics_port = count_to_port(port_to_count(my_node$p) - 1000, tcp);

    redef Broker::metrics_port = my_metrics_port;
    redef Broker::metrics_import_topics = vector();
    redef Broker::metrics_export_topic = "";

With this configuration, the Prometheus server will need to be configured to
scrape each individual Zeek process's port.

As a different example, to only change the port from 9911 to 1234 on the manager
process, but keep the export and import of metrics enabled, use the following snippet::

    @load base/frameworks/cluster

    @ifdef ( Cluster::local_node_type() == Cluster::MANAGER )
    redef Broker::metrics_port = 1234/tcp;
    @endif


Environment variables
^^^^^^^^^^^^^^^^^^^^^

Above Zeek options can also be controlled via environment variables. Instead
of setting :zeek:see:`Broker::metrics_port` in a Zeek script, you can set
the ``BROKER_METRICS_PORT`` environment variable which takes precedence
over the Zeek option.

As with Zeek script options, there are two configuration possibilities for
a cluster. Either configure a unique ``BROKER_METRICS_PORT`` and ``BROKER_ENDPOINT_NAME``
for each of the Zeek processes. Then, setup a Prometheus server to scrape each
of these individual endpoints.
Alternatively, set ``BROKER_METRICS_IMPORT_TOPICS`` and ``BROKER_METRICS_EXPORT_TOPIC``
environment variables appropriately to have a single process, presumably the Zeek manager,
import all metrics from other Zeek processes in a cluster. In this scenario,
set ``BROKER_METRICS_PORT`` only for the Zeek manager and configure the
Prometheus server to scrape just the manager.
