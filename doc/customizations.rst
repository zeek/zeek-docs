.. _popular-customizations:

======================
Popular Customizations
======================

This page outlines customizations and additions that are popular
among Zeek users.

.. note::

  This page lists externally-maintained Zeek packages. The Zeek team does not
  provide support or maintenance for these packages. If you find bugs or have
  feature requests, please reach out to the respective package maintainers directly.

  You may also post in the :slacklink:`Zeek Slack <>` #packages
  channel or :discourselink:`forum <>` to get help from the broader
  Zeek community.


Log Enrichment
==============

Community ID
------------

.. versionadded:: 6.0

Zeek includes native `Community ID Flow Hashing`_ support. This functionality
has previously been provided through the `zeek-community-id`_ package.

.. note::

  At this point, the external `zeek-community-id`_ package is still
  available to support Zeek deployments running older versions. However,
  the scripts provided by the package cause conflicts with those provided in
  Zeek 6.0 - do not load both.

Loading the
:doc:`/scripts/policy/protocols/conn/community-id-logging.zeek`
and
:doc:`/scripts/policy/frameworks/notice/community-id.zeek`
scripts adds an additional ``community_id`` field to the
:zeek:see:`Conn::Info` and :zeek:see:`Notice::Info` record.

.. code-block:: console

   $ zeek -r ./traces/get.trace protocols/conn/community-id-logging LogAscii::use_json=T
   $ jq < conn.log
   {
     "ts": 1362692526.869344,
     "uid": "CoqLmg1Ds5TE61szq1",
     "id.orig_h": "141.142.228.5",
     "id.orig_p": 59856,
     "id.resp_h": "192.150.187.43",
     "id.resp_p": 80,
     "proto": "tcp",
     ...
     "community_id": "1:yvyB8h+3dnggTZW0UEITWCst97w="
   }


The Community ID Flow Hash of a :zeek:see:`conn_id` instance can be computed
with the :zeek:see:`community_id_v1` builtin function directly on the command-line
or used in custom scripts.

.. code-block:: console

    $ zeek -e 'print community_id_v1([$orig_h=141.142.228.5, $orig_p=59856/tcp, $resp_h=192.150.187.43, $resp_p=80/tcp])'
    1:yvyB8h+3dnggTZW0UEITWCst97w=

.. _Community ID Flow Hashing: https://github.com/corelight/community-id-spec
.. _zeek-community-id: https://github.com/corelight/zeek-community-id/>`_


Log Writers
===========

Kafka
-----

For exporting logs to `Apache Kafka`_ in a streaming fashion, the externally-maintained
`zeek-kafka`_ package is a popular choice and easy to configure. It relies on `librdkafka`_.

.. code-block:: zeek

   redef Log::default_writer = Log::WRITER_KAFKAWRITER;

   redef Kafka::kafka_conf += {
       ["metadata.broker.list"] = "192.168.0.1:9092"
   };

.. _Apache Kafka: https://kafka.apache.org/
.. _zeek-kafka: https://github.com/SeisoLLC/zeek-kafka/
.. _librdkafka: https://github.com/confluentinc/librdkafka


Logging
=======

JSON Streaming Logs
-------------------

The externally-maintained `json-streaming-logs`_ package tailors Zeek
for use with log shippers like `Filebeat`_ or `fluentd`_. It configures
additional log files prefixed with ``json_streaming_``, adds ``_path``
and ``_write_ts`` fields to log records and configures log rotation
appropriately.

If you do not use a logging archive and want to stream all logs away
from the system where Zeek is running without leveraging Kafka, this
package helps you with that.

.. _json-streaming-logs: https://github.com/corelight/json-streaming-logs
.. _Filebeat: https://www.elastic.co/beats/filebeat
.. _fluentd: https://www.fluentd.org/


Long Connections
----------------

Zeek logs connection entries into the ``conn.log`` only upon termination
or due to expiration of inactivity timeouts. Depending on the protocol and
chosen timeout values this can significantly delay the appearance of a log
entry for a given connection. The delay may be up to an hour for lingering
SSH connections or connections where the final FIN or RST packets were missed.

The `zeek-long-connections`_ package alleviates this by creating a ``conn_long.log``
log with the same format as ``conn.log``, but containing entries for connections
that have been existing for configurable intervals.
By default, the first entry for a connection is logged after 10mins. Depending on
the environment, this can be lowered as even a 10 minute delay may be significant
for detection purposes in streaming setup.

.. _zeek-long-connections: https://github.com/corelight/zeek-long-connections


Profiling and Debugging
=======================

jemalloc profiling
------------------

For investigation of memory leaks or state-growth issues within Zeek,
jemalloc's profiling is invaluable. A package providing a bit support
for configuring jemalloc's profiling facilities is `zeek-jemalloc-profiling`_.

Some general information about memory profiling exists in the :ref:`Troubleshooting <troubleshooting>`
section.

.. _zeek-jemalloc-profiling: https://github.com/JustinAzoff/zeek-jemalloc-profiling
