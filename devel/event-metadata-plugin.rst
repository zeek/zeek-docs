.. _event-metadata-plugin:

=====================
Event Metadata Plugin
=====================

.. versionadded:: 8.0


Zeek's plugin API allows adding metadata to Zeek events which are then
transported across a Zeek cluster for consumption by other Zeek nodes.
This document describes this functionality in form of a tutorial. We'll
be using custom event metadata identifier to track the latency of Zeek
events in a cluster and record them in a histogram.

If you're unfamiliar with plugin development, head over to the
:ref:`Writing Plugins <writing-plugins>` section.


Registering Metadata
====================

Initially, we make Zeek's core aware of the metadata to attach to events. This
requires two steps.
First, redefining the :zeek:see:`EventMetadata::ID` enumeration with our
custom enumeration value ``WALLCLOCK_TIMESTAMP``. This is our metadata identifier.
It represents the absolute realtime when an event was published in UTC.
Second, registering the metadata identifier with Zeek's :zeek:see:`time` type
by calling :zeek:see:`EventMetadata::register`. This instructs Zeek to convert
metadata items in remote events with identifier ``10001000`` to a
:zeek:see:`time` value.

For simplicity, this is done in the plugin's ``scripts/__init__.zeek`` file
that's loaded automatically when Zeek loads the plugin.

.. literalinclude:: event-metadata-plugin-src/scripts/__load__.zeek
   :caption: main.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

The ``10001000`` represents the metadata identifier for serialization purposes. It
needs to be unique and have a defined meaning and consistent type for a given Zeek
deployment. Metadata identifiers below ``200`` are reserved for Zeek's internal use,
otherwise users are free to choose any value. Zeek will fail to start or fail to
register the type in the case of conflicting identifier uses.


Implementing the Plugin
=======================

Next, we implement the ``InitPostScript()``, ``HookPublishEvent()`` and
``HookQueueEvent()`` methods in our plugin.
In the ``InitPostScript()`` method, a histogram instance is initialized using
Zeek's telemetry manager with hard-coded bounds. These define the latency buckets
for monitoring.
The ``HookPublishEvent()`` method adds ``WALLCLOCK_TIMESTAMP`` metadata with
the current time to the event, while the ``HookQueueEvent()`` method extracts
it from remote events computes the latency based on its own local time. Finally,
the latency is recorded with the histogram by calling ``Observe()``.


.. literalinclude:: event-metadata-plugin-src/src/Plugin.cc
   :caption: main.zeek
   :language: zeek
   :linenos:
   :lines: 28-
   :tab-width: 4


Resulting Prometheus Metrics
============================

Deploying the plugin outlined above in a cluster and querying the manager's
metrics endpoint presents the following result::

    $ curl -s localhost:10001/metrics | grep '^zeek_cluster_event_latency'
    zeek_cluster_event_latency_seconds_count{endpoint="manager"} 11281
    zeek_cluster_event_latency_seconds_sum{endpoint="manager"} 7.960928916931152
    zeek_cluster_event_latency_seconds_bucket{endpoint="manager",le="0.0002"} 37
    zeek_cluster_event_latency_seconds_bucket{endpoint="manager",le="0.0004"} 583
    zeek_cluster_event_latency_seconds_bucket{endpoint="manager",le="0.0005999999999999999"} 3858
    zeek_cluster_event_latency_seconds_bucket{endpoint="manager",le="0.0008"} 7960
    zeek_cluster_event_latency_seconds_bucket{endpoint="manager",le="0.001"} 10185
    zeek_cluster_event_latency_seconds_bucket{endpoint="manager",le="0.0012"} 10957
    zeek_cluster_event_latency_seconds_bucket{endpoint="manager",le="0.0014"} 11239
    zeek_cluster_event_latency_seconds_bucket{endpoint="manager",le="0.0016"} 11269
    zeek_cluster_event_latency_seconds_bucket{endpoint="manager",le="0.0018"} 11279
    zeek_cluster_event_latency_seconds_bucket{endpoint="manager",le="0.002"} 11281
    zeek_cluster_event_latency_seconds_bucket{endpoint="manager",le="+Inf"} 11281


This example indicates that there were a total of 11281 latencies observed,
the summed up latency was around 8 seconds, 37 events had a latency less or equal
to 0.2 milliseconds, 583 with less or equal than 0.4 milliseconds and none
that took more than 2 millisecond.

This data is usually queried and ingested into a Prometheus server and visualized
using Grafana. See also the :ref:`Telemetry framework's <framework-telemetry>`
documentation.
