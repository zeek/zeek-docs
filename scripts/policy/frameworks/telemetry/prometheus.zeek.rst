:tocdepth: 3

policy/frameworks/telemetry/prometheus.zeek
===========================================

In a cluster configuration, open the port number for metrics
from the cluster node configuration for exporting data to
Prometheus.

The manager node will also provide a ``/services.json`` endpoint
for the HTTP Service Discovery system in Prometheus to use for
configuration. This endpoint will include information for all of
the other nodes in the cluster.

:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`

Summary
~~~~~~~

Detailed Interface
~~~~~~~~~~~~~~~~~~

