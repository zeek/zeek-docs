:tocdepth: 3

base/frameworks/broker/main.zeek
================================
.. zeek:namespace:: Broker

The Broker-based communication API and its various options.

:Namespace: Broker
:Imports: :doc:`base/bif/comm.bif.zeek </scripts/base/bif/comm.bif.zeek>`, :doc:`base/bif/messaging.bif.zeek </scripts/base/bif/messaging.bif.zeek>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================== =================================================================
:zeek:id:`Broker::metrics_export_endpoint_name`: :zeek:type:`string` :zeek:attr:`&redef` ID for the metrics exporter.
:zeek:id:`Broker::metrics_export_interval`: :zeek:type:`interval` :zeek:attr:`&redef`    Frequency for publishing scraped metrics to the target topic.
:zeek:id:`Broker::metrics_export_prefixes`: :zeek:type:`vector` :zeek:attr:`&redef`      Selects prefixes from the local metrics.
:zeek:id:`Broker::metrics_export_topic`: :zeek:type:`string` :zeek:attr:`&redef`         Target topic for the metrics.
:zeek:id:`Broker::peer_counts_as_iosource`: :zeek:type:`bool` :zeek:attr:`&redef`        Whether calling :zeek:see:`Broker::peer` will register the Broker
                                                                                         system as an I/O source that will block the process from shutting
                                                                                         down.
======================================================================================== =================================================================

Redefinable Options
###################
==================================================================================== =======================================================================
:zeek:id:`Broker::aggressive_interval`: :zeek:type:`count` :zeek:attr:`&redef`       Frequency of work-stealing polling attempts for Broker/CAF threads
                                                                                     in "aggressive" mode.
:zeek:id:`Broker::aggressive_polls`: :zeek:type:`count` :zeek:attr:`&redef`          Number of work-stealing polling attempts for Broker/CAF threads
                                                                                     in "aggressive" mode.
:zeek:id:`Broker::congestion_queue_size`: :zeek:type:`count` :zeek:attr:`&redef`     The number of buffered messages at the Broker/CAF layer after which
                                                                                     a subscriber considers themselves congested (i.e.
:zeek:id:`Broker::default_connect_retry`: :zeek:type:`interval` :zeek:attr:`&redef`  Default interval to retry connecting to a peer if it cannot be made to
                                                                                     work initially, or if it ever becomes disconnected.
:zeek:id:`Broker::default_listen_address`: :zeek:type:`string` :zeek:attr:`&redef`   Default address on which to listen.
:zeek:id:`Broker::default_listen_retry`: :zeek:type:`interval` :zeek:attr:`&redef`   Default interval to retry listening on a port if it's currently in
                                                                                     use already.
:zeek:id:`Broker::default_log_topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef` The default topic prefix where logs will be published.
:zeek:id:`Broker::default_port`: :zeek:type:`port` :zeek:attr:`&redef`               Default port for Broker communication.
:zeek:id:`Broker::disable_ssl`: :zeek:type:`bool` :zeek:attr:`&redef`                If true, do not use SSL for network connections.
:zeek:id:`Broker::forward_messages`: :zeek:type:`bool` :zeek:attr:`&redef`           Forward all received messages to subscribing peers.
:zeek:id:`Broker::log_batch_interval`: :zeek:type:`interval` :zeek:attr:`&redef`     Max time to buffer log messages before sending the current set out as a
                                                                                     batch.
:zeek:id:`Broker::log_batch_size`: :zeek:type:`count` :zeek:attr:`&redef`            The max number of log entries per log stream to batch together when
                                                                                     sending log messages to a remote logger.
:zeek:id:`Broker::max_threads`: :zeek:type:`count` :zeek:attr:`&redef`               Max number of threads to use for Broker/CAF functionality.
:zeek:id:`Broker::metrics_port`: :zeek:type:`port` :zeek:attr:`&redef`               Port for Broker's metric exporter.
:zeek:id:`Broker::moderate_interval`: :zeek:type:`count` :zeek:attr:`&redef`         Frequency of work-stealing polling attempts for Broker/CAF threads
                                                                                     in "moderate" mode.
:zeek:id:`Broker::moderate_polls`: :zeek:type:`count` :zeek:attr:`&redef`            Number of work-stealing polling attempts for Broker/CAF threads
                                                                                     in "moderate" mode.
:zeek:id:`Broker::moderate_sleep`: :zeek:type:`interval` :zeek:attr:`&redef`         Interval of time for under-utilized Broker/CAF threads to sleep
                                                                                     when in "moderate" mode.
:zeek:id:`Broker::relaxed_interval`: :zeek:type:`count` :zeek:attr:`&redef`          Frequency of work-stealing polling attempts for Broker/CAF threads
                                                                                     in "relaxed" mode.
:zeek:id:`Broker::relaxed_sleep`: :zeek:type:`interval` :zeek:attr:`&redef`          Interval of time for under-utilized Broker/CAF threads to sleep
                                                                                     when in "relaxed" mode.
:zeek:id:`Broker::scheduler_policy`: :zeek:type:`string` :zeek:attr:`&redef`         The CAF scheduling policy to use.
:zeek:id:`Broker::ssl_cafile`: :zeek:type:`string` :zeek:attr:`&redef`               Path to a file containing concatenated trusted certificates
                                                                                     in PEM format.
:zeek:id:`Broker::ssl_capath`: :zeek:type:`string` :zeek:attr:`&redef`               Path to an OpenSSL-style directory of trusted certificates.
:zeek:id:`Broker::ssl_certificate`: :zeek:type:`string` :zeek:attr:`&redef`          Path to a file containing a X.509 certificate for this
                                                                                     node in PEM format.
:zeek:id:`Broker::ssl_keyfile`: :zeek:type:`string` :zeek:attr:`&redef`              Path to the file containing the private key for this node's
                                                                                     certificate.
:zeek:id:`Broker::ssl_passphrase`: :zeek:type:`string` :zeek:attr:`&redef`           Passphrase to decrypt the private key specified by
                                                                                     :zeek:see:`Broker::ssl_keyfile`.
==================================================================================== =======================================================================

Types
#####
====================================================== ====================================================================
:zeek:type:`Broker::Data`: :zeek:type:`record`         Opaque communication data.
:zeek:type:`Broker::DataVector`: :zeek:type:`vector`   Opaque communication data sequence.
:zeek:type:`Broker::EndpointInfo`: :zeek:type:`record` 
:zeek:type:`Broker::ErrorCode`: :zeek:type:`enum`      Enumerates the possible error types.
:zeek:type:`Broker::Event`: :zeek:type:`record`        Opaque event communication data.
:zeek:type:`Broker::NetworkInfo`: :zeek:type:`record`  
:zeek:type:`Broker::PeerInfo`: :zeek:type:`record`     
:zeek:type:`Broker::PeerInfos`: :zeek:type:`vector`    
:zeek:type:`Broker::PeerStatus`: :zeek:type:`enum`     The possible states of a peer endpoint.
:zeek:type:`Broker::TableItem`: :zeek:type:`record`    Opaque communication data used as a convenient way to wrap key-value
                                                       pairs that comprise table entries.
====================================================== ====================================================================

Functions
#########
======================================================================= =======================================================================
:zeek:id:`Broker::auto_publish`: :zeek:type:`function`                  Automatically send an event to any interested peers whenever it is
                                                                        locally dispatched.
:zeek:id:`Broker::auto_unpublish`: :zeek:type:`function`                Stop automatically sending an event to peers upon local dispatch.
:zeek:id:`Broker::default_log_topic`: :zeek:type:`function`             The default implementation for :zeek:see:`Broker::log_topic`.
:zeek:id:`Broker::flush_logs`: :zeek:type:`function`                    Sends all pending log messages to remote peers.
:zeek:id:`Broker::forward`: :zeek:type:`function`                       Register a topic prefix subscription for events that should only be
                                                                        forwarded to any subscribing peers and not raise any event handlers
                                                                        on the receiving/forwarding node.
:zeek:id:`Broker::listen`: :zeek:type:`function`                        Listen for remote connections.
:zeek:id:`Broker::log_topic`: :zeek:type:`function` :zeek:attr:`&redef` A function that will be called for each log entry to determine what
                                                                        broker topic string will be used for sending it to peers.
:zeek:id:`Broker::node_id`: :zeek:type:`function`                       Get a unique identifier for the local broker endpoint.
:zeek:id:`Broker::peer`: :zeek:type:`function`                          Initiate a remote connection.
:zeek:id:`Broker::peers`: :zeek:type:`function`                         Get a list of all peer connections.
:zeek:id:`Broker::publish_id`: :zeek:type:`function`                    Publishes the value of an identifier to a given topic.
:zeek:id:`Broker::subscribe`: :zeek:type:`function`                     Register interest in all peer event messages that use a certain topic
                                                                        prefix.
:zeek:id:`Broker::unpeer`: :zeek:type:`function`                        Remove a remote connection.
:zeek:id:`Broker::unsubscribe`: :zeek:type:`function`                   Unregister interest in all peer event messages that use a topic prefix.
======================================================================= =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Broker::metrics_export_endpoint_name
   :source-code: base/frameworks/broker/main.zeek 149 149

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   ID for the metrics exporter. When setting a target topic for the
   exporter, Broker sets this option to the suffix of the new topic *unless*
   the ID is a non-empty string. Since setting a topic starts the periodic
   publishing of events, we recommend setting the ID always first or avoid
   setting it at all if the topic suffix serves as a good-enough ID. Zeek
   overrides any value provided in zeek_init or earlier at startup if the
   environment variable BROKER_METRICS_ENDPOINT_NAME is defined.

.. zeek:id:: Broker::metrics_export_interval
   :source-code: base/frameworks/broker/main.zeek 134 134

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   Frequency for publishing scraped metrics to the target topic. Zeek
   overrides any value provided in zeek_init or earlier at startup if the
   environment variable BROKER_METRICS_EXPORT_INTERVAL is defined.

.. zeek:id:: Broker::metrics_export_prefixes
   :source-code: base/frameworks/broker/main.zeek 154 154

   :Type: :zeek:type:`vector` of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         []


   Selects prefixes from the local metrics. Only metrics with prefixes
   listed in this variable are included when publishing local metrics.
   Setting an empty vector selects *all* metrics.

.. zeek:id:: Broker::metrics_export_topic
   :source-code: base/frameworks/broker/main.zeek 140 140

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Target topic for the metrics. Setting a non-empty string starts the
   periodic publishing of local metrics. Zeek overrides any value provided in
   zeek_init or earlier at startup if the environment variable
   BROKER_METRICS_EXPORT_TOPIC is defined.

.. zeek:id:: Broker::peer_counts_as_iosource
   :source-code: base/frameworks/broker/main.zeek 123 123

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Whether calling :zeek:see:`Broker::peer` will register the Broker
   system as an I/O source that will block the process from shutting
   down.  For example, set this to false when you are reading pcaps,
   but also want to initaiate a Broker peering and still shutdown after
   done reading the pcap.

Redefinable Options
###################
.. zeek:id:: Broker::aggressive_interval
   :source-code: base/frameworks/broker/main.zeek 105 105

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``4``

   Frequency of work-stealing polling attempts for Broker/CAF threads
   in "aggressive" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::aggressive_polls
   :source-code: base/frameworks/broker/main.zeek 97 97

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5``

   Number of work-stealing polling attempts for Broker/CAF threads
   in "aggressive" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::congestion_queue_size
   :source-code: base/frameworks/broker/main.zeek 62 62

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``200``

   The number of buffered messages at the Broker/CAF layer after which
   a subscriber considers themselves congested (i.e. tune the congestion
   control mechanisms).

.. zeek:id:: Broker::default_connect_retry
   :source-code: base/frameworks/broker/main.zeek 26 26

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``30.0 secs``

   Default interval to retry connecting to a peer if it cannot be made to
   work initially, or if it ever becomes disconnected.  Use of the
   ZEEK_DEFAULT_CONNECT_RETRY environment variable (set as number of
   seconds) will override this option and also any values given to
   :zeek:see:`Broker::peer`.

.. zeek:id:: Broker::default_listen_address
   :source-code: base/frameworks/broker/main.zeek 19 19

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Default address on which to listen.
   
   .. zeek:see:: Broker::listen

.. zeek:id:: Broker::default_listen_retry
   :source-code: base/frameworks/broker/main.zeek 14 14

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``30.0 secs``

   Default interval to retry listening on a port if it's currently in
   use already.  Use of the ZEEK_DEFAULT_LISTEN_RETRY environment variable
   (set as a number of seconds) will override this option and also
   any values given to :zeek:see:`Broker::listen`.

.. zeek:id:: Broker::default_log_topic_prefix
   :source-code: base/frameworks/broker/main.zeek 158 158

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/logs/"``

   The default topic prefix where logs will be published.  The log's stream
   id is appended when writing to a particular stream.

.. zeek:id:: Broker::default_port
   :source-code: base/frameworks/broker/main.zeek 8 8

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``9999/tcp``

   Default port for Broker communication. Where not specified
   otherwise, this is the port to connect to and listen on.

.. zeek:id:: Broker::disable_ssl
   :source-code: base/frameworks/broker/main.zeek 32 32

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, do not use SSL for network connections. By default, SSL will
   even be used if no certificates / CAs have been configured. In that case
   (which is the default) the communication will be encrypted, but not
   authenticated.

.. zeek:id:: Broker::forward_messages
   :source-code: base/frameworks/broker/main.zeek 116 116

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Forward all received messages to subscribing peers.

.. zeek:id:: Broker::log_batch_interval
   :source-code: base/frameworks/broker/main.zeek 70 70

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   Max time to buffer log messages before sending the current set out as a
   batch.

.. zeek:id:: Broker::log_batch_size
   :source-code: base/frameworks/broker/main.zeek 66 66

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``400``

   The max number of log entries per log stream to batch together when
   sending log messages to a remote logger.

.. zeek:id:: Broker::max_threads
   :source-code: base/frameworks/broker/main.zeek 74 74

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1``

   Max number of threads to use for Broker/CAF functionality.  The
   ZEEK_BROKER_MAX_THREADS environment variable overrides this setting.

.. zeek:id:: Broker::metrics_port
   :source-code: base/frameworks/broker/main.zeek 129 129

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0/unknown``

   Port for Broker's metric exporter. Setting this to a valid TCP port causes
   Broker to make metrics available to Prometheus scrapers via HTTP. Zeek
   overrides any value provided in zeek_init or earlier at startup if the
   environment variable BROKER_METRICS_PORT is defined.

.. zeek:id:: Broker::moderate_interval
   :source-code: base/frameworks/broker/main.zeek 109 109

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2``

   Frequency of work-stealing polling attempts for Broker/CAF threads
   in "moderate" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::moderate_polls
   :source-code: base/frameworks/broker/main.zeek 101 101

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5``

   Number of work-stealing polling attempts for Broker/CAF threads
   in "moderate" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::moderate_sleep
   :source-code: base/frameworks/broker/main.zeek 89 89

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``16.0 msecs``

   Interval of time for under-utilized Broker/CAF threads to sleep
   when in "moderate" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::relaxed_interval
   :source-code: base/frameworks/broker/main.zeek 113 113

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1``

   Frequency of work-stealing polling attempts for Broker/CAF threads
   in "relaxed" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::relaxed_sleep
   :source-code: base/frameworks/broker/main.zeek 93 93

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``64.0 msecs``

   Interval of time for under-utilized Broker/CAF threads to sleep
   when in "relaxed" mode.  Only used for the "stealing" scheduler policy.

.. zeek:id:: Broker::scheduler_policy
   :source-code: base/frameworks/broker/main.zeek 85 85

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"sharing"``

   The CAF scheduling policy to use.  Available options are "sharing" and
   "stealing".  The "sharing" policy uses a single, global work queue along
   with mutex and condition variable used for accessing it, which may be
   better for cases that don't require much concurrency or need lower power
   consumption.  The "stealing" policy uses multiple work queues protected
   by spinlocks, which may be better for use-cases that have more
   concurrency needs.  E.g. may be worth testing the "stealing" policy
   along with dedicating more threads if a lot of data store processing is
   required.

.. zeek:id:: Broker::ssl_cafile
   :source-code: base/frameworks/broker/main.zeek 37 37

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Path to a file containing concatenated trusted certificates
   in PEM format. If set, Zeek will require valid certificates for
   all peers.

.. zeek:id:: Broker::ssl_capath
   :source-code: base/frameworks/broker/main.zeek 42 42

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Path to an OpenSSL-style directory of trusted certificates.
   If set, Zeek will require valid certificates for
   all peers.

.. zeek:id:: Broker::ssl_certificate
   :source-code: base/frameworks/broker/main.zeek 47 47

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Path to a file containing a X.509 certificate for this
   node in PEM format. If set, Zeek will require valid certificates for
   all peers.

.. zeek:id:: Broker::ssl_keyfile
   :source-code: base/frameworks/broker/main.zeek 57 57

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Path to the file containing the private key for this node's
   certificate. If set, Zeek will require valid certificates for
   all peers.

.. zeek:id:: Broker::ssl_passphrase
   :source-code: base/frameworks/broker/main.zeek 52 52

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Passphrase to decrypt the private key specified by
   :zeek:see:`Broker::ssl_keyfile`. If set, Zeek will require valid
   certificates for all peers.

Types
#####
.. zeek:type:: Broker::Data
   :source-code: base/frameworks/broker/main.zeek 248 250

   :Type: :zeek:type:`record`

      data: :zeek:type:`opaque` of Broker::Data :zeek:attr:`&optional`

   Opaque communication data.

.. zeek:type:: Broker::DataVector
   :source-code: base/frameworks/broker/main.zeek 253 253

   :Type: :zeek:type:`vector` of :zeek:type:`Broker::Data`

   Opaque communication data sequence.

.. zeek:type:: Broker::EndpointInfo
   :source-code: base/frameworks/broker/main.zeek 233 238

   :Type: :zeek:type:`record`

      id: :zeek:type:`string`
         A unique identifier of the node.

      network: :zeek:type:`Broker::NetworkInfo` :zeek:attr:`&optional`
         Network-level information.


.. zeek:type:: Broker::ErrorCode
   :source-code: base/frameworks/broker/main.zeek 179 179

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::NO_ERROR Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::UNSPECIFIED Broker::ErrorCode

         The unspecified default error code.

      .. zeek:enum:: Broker::PEER_INCOMPATIBLE Broker::ErrorCode

         Version incompatibility.

      .. zeek:enum:: Broker::PEER_INVALID Broker::ErrorCode

         Referenced peer does not exist.

      .. zeek:enum:: Broker::PEER_UNAVAILABLE Broker::ErrorCode

         Remote peer not listening.

      .. zeek:enum:: Broker::PEER_DISCONNECT_DURING_HANDSHAKE Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::PEER_TIMEOUT Broker::ErrorCode

         A peering request timed out.

      .. zeek:enum:: Broker::MASTER_EXISTS Broker::ErrorCode

         Master with given name already exists.

      .. zeek:enum:: Broker::NO_SUCH_MASTER Broker::ErrorCode

         Master with given name does not exist.

      .. zeek:enum:: Broker::NO_SUCH_KEY Broker::ErrorCode

         The given data store key does not exist.

      .. zeek:enum:: Broker::REQUEST_TIMEOUT Broker::ErrorCode

         The store operation timed out.

      .. zeek:enum:: Broker::TYPE_CLASH Broker::ErrorCode

         The operation expected a different type than provided.

      .. zeek:enum:: Broker::INVALID_DATA Broker::ErrorCode

         The data value cannot be used to carry out the desired operation.

      .. zeek:enum:: Broker::BACKEND_FAILURE Broker::ErrorCode

         The storage backend failed to execute the operation.

      .. zeek:enum:: Broker::STALE_DATA Broker::ErrorCode

         The storage backend failed to execute the operation.

      .. zeek:enum:: Broker::CANNOT_OPEN_FILE Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::CANNOT_WRITE_FILE Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::INVALID_TOPIC_KEY Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::END_OF_FILE Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::INVALID_TAG Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::INVALID_STATUS Broker::ErrorCode

         (present if :doc:`/scripts/base/bif/comm.bif.zeek` is loaded)


      .. zeek:enum:: Broker::CAF_ERROR Broker::ErrorCode

         Catch-all for a CAF-level problem.

   Enumerates the possible error types.

.. zeek:type:: Broker::Event
   :source-code: base/frameworks/broker/main.zeek 256 261

   :Type: :zeek:type:`record`

      name: :zeek:type:`string` :zeek:attr:`&optional`
         The name of the event.  Not set if invalid event or arguments.

      args: :zeek:type:`Broker::DataVector`
         The arguments to the event.

   Opaque event communication data.

.. zeek:type:: Broker::NetworkInfo
   :source-code: base/frameworks/broker/main.zeek 226 231

   :Type: :zeek:type:`record`

      address: :zeek:type:`string` :zeek:attr:`&log`
         The IP address or hostname where the endpoint listens.

      bound_port: :zeek:type:`port` :zeek:attr:`&log`
         The port where the endpoint is bound to.


.. zeek:type:: Broker::PeerInfo
   :source-code: base/frameworks/broker/main.zeek 240 243

   :Type: :zeek:type:`record`

      peer: :zeek:type:`Broker::EndpointInfo`

      status: :zeek:type:`Broker::PeerStatus`


.. zeek:type:: Broker::PeerInfos
   :source-code: base/frameworks/broker/main.zeek 245 245

   :Type: :zeek:type:`vector` of :zeek:type:`Broker::PeerInfo`


.. zeek:type:: Broker::PeerStatus
   :source-code: base/frameworks/broker/main.zeek 211 211

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::INITIALIZING Broker::PeerStatus

         The peering process is initiated.

      .. zeek:enum:: Broker::CONNECTING Broker::PeerStatus

         Connection establishment in process.

      .. zeek:enum:: Broker::CONNECTED Broker::PeerStatus

         Connection established, peering pending.

      .. zeek:enum:: Broker::PEERED Broker::PeerStatus

         Successfully peered.

      .. zeek:enum:: Broker::DISCONNECTED Broker::PeerStatus

         Connection to remote peer lost.

      .. zeek:enum:: Broker::RECONNECTING Broker::PeerStatus

         Reconnecting to peer after a lost connection.

   The possible states of a peer endpoint.

.. zeek:type:: Broker::TableItem
   :source-code: base/frameworks/broker/main.zeek 265 268

   :Type: :zeek:type:`record`

      key: :zeek:type:`Broker::Data`

      val: :zeek:type:`Broker::Data`

   Opaque communication data used as a convenient way to wrap key-value
   pairs that comprise table entries.

Functions
#########
.. zeek:id:: Broker::auto_publish
   :source-code: base/frameworks/broker/main.zeek 537 540

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`, ev: :zeek:type:`any`) : :zeek:type:`bool`

   Automatically send an event to any interested peers whenever it is
   locally dispatched. (For example, using "event my_event(...);" in a
   script.)
   

   :topic: a topic string associated with the event message.
          Peers advertise interest by registering a subscription to some
          prefix of this topic name.
   

   :ev: a Zeek event value.
   

   :returns: true if automatic event sending is now enabled.

.. zeek:id:: Broker::auto_unpublish
   :source-code: base/frameworks/broker/main.zeek 542 545

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`, ev: :zeek:type:`any`) : :zeek:type:`bool`

   Stop automatically sending an event to peers upon local dispatch.
   

   :topic: a topic originally given to :zeek:see:`Broker::auto_publish`.
   

   :ev: an event originally given to :zeek:see:`Broker::auto_publish`.
   

   :returns: true if automatic events will not occur for the topic/event
            pair.

.. zeek:id:: Broker::default_log_topic
   :source-code: base/frameworks/broker/main.zeek 161 164

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, path: :zeek:type:`string`) : :zeek:type:`string`

   The default implementation for :zeek:see:`Broker::log_topic`.

.. zeek:id:: Broker::flush_logs
   :source-code: base/frameworks/broker/main.zeek 512 515

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Sends all pending log messages to remote peers.  This normally
   doesn't need to be used except for test cases that are time-sensitive.

.. zeek:id:: Broker::forward
   :source-code: base/frameworks/broker/main.zeek 527 530

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`

   Register a topic prefix subscription for events that should only be
   forwarded to any subscribing peers and not raise any event handlers
   on the receiving/forwarding node.  i.e. it's the same as
   :zeek:see:`Broker::subscribe` except matching events are not raised
   on the receiver, just forwarded.  Use :zeek:see:`Broker::unsubscribe`
   with the same argument to undo this operation.
   

   :topic_prefix: a prefix to match against remote message topics.
                 e.g. an empty prefix matches everything and "a" matches
                 "alice" and "amy" but not "bob".
   

   :returns: true if a new event forwarding/subscription is now registered.

.. zeek:id:: Broker::listen
   :source-code: base/frameworks/broker/main.zeek 474 490

   :Type: :zeek:type:`function` (a: :zeek:type:`string` :zeek:attr:`&default` = :zeek:see:`Broker::default_listen_address` :zeek:attr:`&optional`, p: :zeek:type:`port` :zeek:attr:`&default` = :zeek:see:`Broker::default_port` :zeek:attr:`&optional`, retry: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_listen_retry` :zeek:attr:`&optional`) : :zeek:type:`port`

   Listen for remote connections.
   

   :a: an address string on which to accept connections, e.g.
      "127.0.0.1".  An empty string refers to INADDR_ANY.
   

   :p: the TCP port to listen on. The value 0 means that the OS should choose
      the next available free port.
   

   :retry: If non-zero, retries listening in regular intervals if the port cannot be
          acquired immediately. 0 disables retries.  If the
          ZEEK_DEFAULT_LISTEN_RETRY environment variable is set (as number
          of seconds), it overrides any value given here.
   

   :returns: the bound port or 0/? on failure.
   
   .. zeek:see:: Broker::status

.. zeek:id:: Broker::log_topic
   :source-code: base/frameworks/broker/main.zeek 161 164

   :Type: :zeek:type:`function` (id: :zeek:type:`Log::ID`, path: :zeek:type:`string`) : :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`

   A function that will be called for each log entry to determine what
   broker topic string will be used for sending it to peers.  The
   default implementation will return a value based on
   :zeek:see:`Broker::default_log_topic_prefix`.
   

   :id: the ID associated with the log stream entry that will be sent.
   

   :path: the path to which the log stream entry will be output.
   

   :returns: a string representing the broker topic to which the log
            will be sent.

.. zeek:id:: Broker::node_id
   :source-code: base/frameworks/broker/main.zeek 507 510

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Get a unique identifier for the local broker endpoint.
   

   :returns: a unique identifier for the local broker endpoint.

.. zeek:id:: Broker::peer
   :source-code: base/frameworks/broker/main.zeek 492 495

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port` :zeek:attr:`&default` = :zeek:see:`Broker::default_port` :zeek:attr:`&optional`, retry: :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`Broker::default_connect_retry` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Initiate a remote connection.
   

   :a: an address to connect to, e.g. "localhost" or "127.0.0.1".
   

   :p: the TCP port on which the remote side is listening.
   

   :retry: an interval at which to retry establishing the
          connection with the remote peer if it cannot be made initially, or
          if it ever becomes disconnected.  If the
          ZEEK_DEFAULT_CONNECT_RETRY environment variable is set (as number
          of seconds), it overrides any value given here.
   

   :returns: true if it's possible to try connecting with the peer and
            it's a new peer. The actual connection may not be established
            until a later point in time.
   
   .. zeek:see:: Broker::status

.. zeek:id:: Broker::peers
   :source-code: base/frameworks/broker/main.zeek 502 505

   :Type: :zeek:type:`function` () : :zeek:type:`vector` of :zeek:type:`Broker::PeerInfo`

   Get a list of all peer connections.
   

   :returns: a list of all peer connections.

.. zeek:id:: Broker::publish_id
   :source-code: base/frameworks/broker/main.zeek 517 520

   :Type: :zeek:type:`function` (topic: :zeek:type:`string`, id: :zeek:type:`string`) : :zeek:type:`bool`

   Publishes the value of an identifier to a given topic.  The subscribers
   will update their local value for that identifier on receipt.
   

   :topic: a topic associated with the message.
   

   :id: the identifier to publish.
   

   :returns: true if the message is sent.

.. zeek:id:: Broker::subscribe
   :source-code: base/frameworks/broker/main.zeek 522 525

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`

   Register interest in all peer event messages that use a certain topic
   prefix.  Note that subscriptions may not be altered immediately after
   calling (except during :zeek:see:`zeek_init`).
   

   :topic_prefix: a prefix to match against remote message topics.
                 e.g. an empty prefix matches everything and "a" matches
                 "alice" and "amy" but not "bob".
   

   :returns: true if it's a new event subscription and it is now registered.

.. zeek:id:: Broker::unpeer
   :source-code: base/frameworks/broker/main.zeek 497 500

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`bool`

   Remove a remote connection.
   
   Note that this does not terminate the connection to the peer, it
   just means that we won't exchange any further information with it
   unless peering resumes later.
   

   :a: the address used in previous successful call to :zeek:see:`Broker::peer`.
   

   :p: the port used in previous successful call to :zeek:see:`Broker::peer`.
   

   :returns: true if the arguments match a previously successful call to
            :zeek:see:`Broker::peer`.
   

   :TODO: We do not have a function yet to terminate a connection.

.. zeek:id:: Broker::unsubscribe
   :source-code: base/frameworks/broker/main.zeek 532 535

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`

   Unregister interest in all peer event messages that use a topic prefix.
   Note that subscriptions may not be altered immediately after calling
   (except during :zeek:see:`zeek_init`).
   

   :topic_prefix: a prefix previously supplied to a successful call to
                 :zeek:see:`Broker::subscribe` or :zeek:see:`Broker::forward`.
   

   :returns: true if interest in the topic prefix is no longer advertised.


