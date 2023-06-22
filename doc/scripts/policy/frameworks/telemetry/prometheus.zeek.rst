:tocdepth: 3

policy/frameworks/telemetry/prometheus.zeek
===========================================

In a cluster configuration, open port 9911 on the manager for
Prometheus exposition and import all metrics from the
`zeek/cluster/metrics/...` topic.

For customization or disabling, redef the involved Broker options again.
Specifically, to disable listening on port 9911, set
:zeek:see:`Broker::metrics_port` to `0/unknown` again.

Note that in large clusters, metrics import may cause significant
communication overhead as well as load on the manager.


:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`

Summary
~~~~~~~

Detailed Interface
~~~~~~~~~~~~~~~~~~

