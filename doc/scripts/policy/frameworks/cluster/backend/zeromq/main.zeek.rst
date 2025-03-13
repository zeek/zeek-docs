:tocdepth: 3

policy/frameworks/cluster/backend/zeromq/main.zeek
==================================================
.. zeek:namespace:: Cluster::Backend::ZeroMQ

ZeroMQ cluster backend support.

For publish-subscribe functionality, one node in the Zeek cluster spawns a
thread running a central broker listening on a XPUB and XSUB socket.
These sockets are connected via `zmq_proxy() <https://libzmq.readthedocs.io/en/latest/zmq_proxy.html>`_.
All other nodes connect to this central broker with their own XSUB and
XPUB sockets, establishing a global many-to-many publish-subscribe system
where each node sees subscriptions and messages from all other nodes in a
Zeek cluster. ZeroMQ's `publish-subscribe pattern <http://api.zeromq.org/4-2:zmq-socket#toc9>`_
documentation may be a good starting point. Elsewhere in ZeroMQ's documentation,
the central broker is also called `forwarder <http://api.zeromq.org/4-2:zmq-proxy#toc5>`_.

For remote logging functionality, the ZeroMQ `pipeline pattern <http://api.zeromq.org/4-2:zmq-socket#toc14>`_
is used. All logger nodes listen on a PULL socket. Other nodes connect
via PUSH sockets to all of the loggers. Concretely, remote logging
functionality is not publish-subscribe, but instead leverages ZeroMQ's
built-in load-balancing functionality provided by PUSH and PULL
sockets.

The ZeroMQ cluster backend technically allows to run a non-Zeek central
broker (it only needs to offer XPUB and XSUB sockets). Further, it is
possible to run non-Zeek logger nodes. All a logger node needs to do is
open a ZeroMQ PULL socket and interpret the format used by Zeek nodes
to send their log writes.

:Namespace: Cluster::Backend::ZeroMQ

Summary
~~~~~~~
Redefinable Options
###################
=================================================================================================== ==================================================================
:zeek:id:`Cluster::Backend::ZeroMQ::connect_log_endpoints`: :zeek:type:`vector` :zeek:attr:`&redef` Vector of ZeroMQ endpoints to connect to for logging.
:zeek:id:`Cluster::Backend::ZeroMQ::connect_xpub_endpoint`: :zeek:type:`string` :zeek:attr:`&redef` The central broker's XPUB endpoint to connect to.
:zeek:id:`Cluster::Backend::ZeroMQ::connect_xpub_nodrop`: :zeek:type:`bool` :zeek:attr:`&redef`     Do not silently drop messages if high-water-mark is reached.
:zeek:id:`Cluster::Backend::ZeroMQ::connect_xsub_endpoint`: :zeek:type:`string` :zeek:attr:`&redef` The central broker's XSUB endpoint to connect to.
:zeek:id:`Cluster::Backend::ZeroMQ::debug_flags`: :zeek:type:`count` :zeek:attr:`&redef`            Bitmask to enable low-level stderr based debug printing.
:zeek:id:`Cluster::Backend::ZeroMQ::hello_expiration`: :zeek:type:`interval` :zeek:attr:`&redef`    Expiration for hello state.
:zeek:id:`Cluster::Backend::ZeroMQ::linger_ms`: :zeek:type:`int` :zeek:attr:`&redef`                Configure the ZeroMQ's sockets linger value.
:zeek:id:`Cluster::Backend::ZeroMQ::listen_log_endpoint`: :zeek:type:`string` :zeek:attr:`&redef`   PULL socket address to listen on for log messages.
:zeek:id:`Cluster::Backend::ZeroMQ::listen_xpub_endpoint`: :zeek:type:`string` :zeek:attr:`&redef`  XPUB listen endpoint for the central broker.
:zeek:id:`Cluster::Backend::ZeroMQ::listen_xpub_nodrop`: :zeek:type:`bool` :zeek:attr:`&redef`      Do not silently drop messages if high-water-mark is reached.
:zeek:id:`Cluster::Backend::ZeroMQ::listen_xsub_endpoint`: :zeek:type:`string` :zeek:attr:`&redef`  XSUB listen endpoint for the central broker.
:zeek:id:`Cluster::Backend::ZeroMQ::log_immediate`: :zeek:type:`bool` :zeek:attr:`&redef`           Configure ZeroMQ's immediate setting on PUSH sockets
:zeek:id:`Cluster::Backend::ZeroMQ::log_rcvbuf`: :zeek:type:`int` :zeek:attr:`&redef`               Kernel receive buffer size for log sockets.
:zeek:id:`Cluster::Backend::ZeroMQ::log_rcvhwm`: :zeek:type:`int` :zeek:attr:`&redef`               Receive high water mark value for the log PULL sockets.
:zeek:id:`Cluster::Backend::ZeroMQ::log_sndbuf`: :zeek:type:`int` :zeek:attr:`&redef`               Kernel transmit buffer size for log sockets.
:zeek:id:`Cluster::Backend::ZeroMQ::log_sndhwm`: :zeek:type:`int` :zeek:attr:`&redef`               Send high water mark value for the log PUSH sockets.
:zeek:id:`Cluster::Backend::ZeroMQ::poll_max_messages`: :zeek:type:`count` :zeek:attr:`&redef`      Messages to receive before yielding.
:zeek:id:`Cluster::Backend::ZeroMQ::proxy_io_threads`: :zeek:type:`count` :zeek:attr:`&redef`       How many IO threads to configure for the ZeroMQ context that
                                                                                                    acts as a central broker.
:zeek:id:`Cluster::Backend::ZeroMQ::run_proxy_thread`: :zeek:type:`bool` :zeek:attr:`&redef`        Toggle for running a central ZeroMQ XPUB-XSUB broker on this node.
=================================================================================================== ==================================================================

State Variables
###############
================================================================================================= ================================
:zeek:id:`Cluster::Backend::ZeroMQ::node_topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`   The node topic prefix to use.
:zeek:id:`Cluster::Backend::ZeroMQ::nodeid_topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef` The node_id topic prefix to use.
================================================================================================= ================================

Redefinitions
#############
============================================================================================ =
:zeek:id:`Cluster::Backend::ZeroMQ::run_proxy_thread`: :zeek:type:`bool` :zeek:attr:`&redef` 
:zeek:id:`Cluster::backend`: :zeek:type:`Cluster::BackendTag` :zeek:attr:`&redef`            
:zeek:id:`Cluster::logger_pool_spec`: :zeek:type:`Cluster::PoolSpec` :zeek:attr:`&redef`     
:zeek:id:`Cluster::logger_topic`: :zeek:type:`string` :zeek:attr:`&redef`                    
:zeek:id:`Cluster::manager_topic`: :zeek:type:`string` :zeek:attr:`&redef`                   
:zeek:id:`Cluster::node_id`: :zeek:type:`function` :zeek:attr:`&redef`                       
:zeek:id:`Cluster::node_topic`: :zeek:type:`function` :zeek:attr:`&redef`                    
:zeek:id:`Cluster::nodeid_topic`: :zeek:type:`function` :zeek:attr:`&redef`                  
:zeek:id:`Cluster::proxy_pool_spec`: :zeek:type:`Cluster::PoolSpec` :zeek:attr:`&redef`      
:zeek:id:`Cluster::proxy_topic`: :zeek:type:`string` :zeek:attr:`&redef`                     
:zeek:id:`Cluster::worker_pool_spec`: :zeek:type:`Cluster::PoolSpec` :zeek:attr:`&redef`     
:zeek:id:`Cluster::worker_topic`: :zeek:type:`string` :zeek:attr:`&redef`                    
============================================================================================ =

Events
######
======================================================================= =================================================================
:zeek:id:`Cluster::Backend::ZeroMQ::hello`: :zeek:type:`event`          Low-level event send to a node in response to their subscription.
:zeek:id:`Cluster::Backend::ZeroMQ::subscription`: :zeek:type:`event`   Low-level event when a subscription is added.
:zeek:id:`Cluster::Backend::ZeroMQ::unsubscription`: :zeek:type:`event` Low-level event when a subscription vanishes.
======================================================================= =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Cluster::Backend::ZeroMQ::connect_log_endpoints
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 45 45

   :Type: :zeek:type:`vector` of :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         []


   Vector of ZeroMQ endpoints to connect to for logging.
   
   A node's PUSH socket used for logging connects to each
   of the ZeroMQ endpoints listed in this vector.

.. zeek:id:: Cluster::Backend::ZeroMQ::connect_xpub_endpoint
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 32 32

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"tcp://127.0.0.1:5556"``

   The central broker's XPUB endpoint to connect to.
   
   A node connects with its XSUB socket to the XPUB socket
   of the central broker.

.. zeek:id:: Cluster::Backend::ZeroMQ::connect_xpub_nodrop
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 150 150

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Do not silently drop messages if high-water-mark is reached.
   
   Whether to configure ``ZMQ_XPUB_NODROP`` on the XPUB socket
   connecting to the proxy to detect when sending a message fails
   due to reaching the high-water-mark.
   
   See ZeroMQ's `ZMQ_XPUB_NODROP documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc61>`_
   for more details.

.. zeek:id:: Cluster::Backend::ZeroMQ::connect_xsub_endpoint
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 39 39

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"tcp://127.0.0.1:5555"``

   The central broker's XSUB endpoint to connect to.
   
   A node connects with its XPUB socket to the XSUB socket
   of the central broker.

.. zeek:id:: Cluster::Backend::ZeroMQ::debug_flags
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 180 180

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   Bitmask to enable low-level stderr based debug printing.
   
       poll:   1 (produce verbose zmq::poll() output)
       thread: 2 (produce thread related output)
   
   Or values from the above list together and set debug_flags
   to the result. E.g. use 7 to select 4, 2 and 1. Only use this
   in development if something seems off. The thread used internally
   will produce output on stderr.

.. zeek:id:: Cluster::Backend::ZeroMQ::hello_expiration
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 220 220

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 secs``

   Expiration for hello state.
   
   How long to wait before expiring information about
   subscriptions and hello messages from other
   nodes. These expirations trigger reporter warnings.

.. zeek:id:: Cluster::Backend::ZeroMQ::linger_ms
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 95 95

   :Type: :zeek:type:`int`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``500``

   Configure the ZeroMQ's sockets linger value.
   
   The default used by libzmq is 30 seconds (30 000) which is very long
   when loggers vanish before workers during a shutdown, so we reduce
   this to 500 milliseconds by default.
   
   A value of ``-1`` configures blocking forever, while ``0`` would
   immediately discard any pending messages.
   
   See ZeroMQ's `ZMQ_LINGER documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc24>`_
   for more details.

.. zeek:id:: Cluster::Backend::ZeroMQ::listen_log_endpoint
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 82 82

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   PULL socket address to listen on for log messages.
   
   If empty, don't listen for log messages, otherwise
   a ZeroMQ address to bind to. E.g., ``tcp://127.0.0.1:5555``.

.. zeek:id:: Cluster::Backend::ZeroMQ::listen_xpub_endpoint
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 76 76

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"tcp://127.0.0.1:5555"``

   XPUB listen endpoint for the central broker.
   
   This setting is used for the XPUB socket of the central broker started
   when :zeek:see:`Cluster::Backend::ZeroMQ::run_proxy_thread` is ``T``.

.. zeek:id:: Cluster::Backend::ZeroMQ::listen_xpub_nodrop
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 163 163

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Do not silently drop messages if high-water-mark is reached.
   
   Whether to configure ``ZMQ_XPUB_NODROP`` on the XPUB socket
   to detect when sending a message fails due to reaching
   the high-water-mark.
   
   This setting applies to the XPUB/XSUB broker started when
   :zeek:see:`Cluster::Backend::ZeroMQ::run_proxy_thread` is ``T``.
   
   See ZeroMQ's `ZMQ_XPUB_NODROP documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc61>`_
   for more details.

.. zeek:id:: Cluster::Backend::ZeroMQ::listen_xsub_endpoint
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 70 70

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"tcp://127.0.0.1:5556"``

   XSUB listen endpoint for the central broker.
   
   This setting is used for the XSUB socket of the central broker started
   when :zeek:see:`Cluster::Backend::ZeroMQ::run_proxy_thread` is ``T``.

.. zeek:id:: Cluster::Backend::ZeroMQ::log_immediate
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 105 105

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Configure ZeroMQ's immediate setting on PUSH sockets
   
   Setting this to ``T`` will queue log writes only to completed
   connections. By default, log writes are queued to all potential
   endpoints listed in :zeek:see:`Cluster::Backend::ZeroMQ::connect_log_endpoints`.
   
   See ZeroMQ's `ZMQ_IMMEDIATE documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc21>`_
   for more details.

.. zeek:id:: Cluster::Backend::ZeroMQ::log_rcvbuf
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 140 140

   :Type: :zeek:type:`int`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``-1``

   Kernel receive buffer size for log sockets.
   
   Using -1 will use the kernel's default.
   
   See ZeroMQ's `ZMQ_RCVBUF documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc34>`_
   for more details.

.. zeek:id:: Cluster::Backend::ZeroMQ::log_rcvhwm
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 125 125

   :Type: :zeek:type:`int`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1000``

   Receive high water mark value for the log PULL sockets.
   
   If reached, Zeek workers will block or drop messages.
   
   See ZeroMQ's `ZMQ_RCVHWM documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc35>`_
   for more details.
   
   TODO: Make action configurable (block vs drop)

.. zeek:id:: Cluster::Backend::ZeroMQ::log_sndbuf
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 132 132

   :Type: :zeek:type:`int`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``-1``

   Kernel transmit buffer size for log sockets.
   
   Using -1 will use the kernel's default.
   
   See ZeroMQ's `ZMQ_SNDBUF documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc45>`_.

.. zeek:id:: Cluster::Backend::ZeroMQ::log_sndhwm
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 115 115

   :Type: :zeek:type:`int`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1000``

   Send high water mark value for the log PUSH sockets.
   
   If reached, Zeek nodes will block or drop messages.
   
   See ZeroMQ's `ZMQ_SNDHWM documentation <http://api.zeromq.org/4-2:zmq-setsockopt#toc46>`_
   for more details.
   
   TODO: Make action configurable (block vs drop)

.. zeek:id:: Cluster::Backend::ZeroMQ::poll_max_messages
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 169 169

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100``

   Messages to receive before yielding.
   
   Yield from the receive loop when this many messages have been
   received from one of the used sockets.

.. zeek:id:: Cluster::Backend::ZeroMQ::proxy_io_threads
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 64 64

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2``

   How many IO threads to configure for the ZeroMQ context that
   acts as a central broker.
   See ZeroMQ's `ZMQ_IO_THREADS documentation <http://api.zeromq.org/4-2:zmq-ctx-set#toc4>`_
   and the `I/O threads <https://zguide.zeromq.org/docs/chapter2/#I-O-Threads>`_
   section in the ZeroMQ guide for details.

.. zeek:id:: Cluster::Backend::ZeroMQ::run_proxy_thread
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 56 56

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``
   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/backend/zeromq/main.zeek`

      ``=``::

         Cluster::local_node_type() == Cluster::MANAGER


   Toggle for running a central ZeroMQ XPUB-XSUB broker on this node.
   
   If set to ``T``, :zeek:see:`Cluster::Backend::ZeroMQ::spawn_zmq_proxy_thread`
   is called during :zeek:see:`zeek_init`. The node will listen
   on :zeek:see:`Cluster::Backend::ZeroMQ::listen_xsub_endpoint` and
   :zeek:see:`Cluster::Backend::ZeroMQ::listen_xpub_endpoint` and
   forward subscriptions and messages between nodes.
   
   By default, this is set to ``T`` on the manager and ``F`` elsewhere.

State Variables
###############
.. zeek:id:: Cluster::Backend::ZeroMQ::node_topic_prefix
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 183 183

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek.cluster.node"``

   The node topic prefix to use.

.. zeek:id:: Cluster::Backend::ZeroMQ::nodeid_topic_prefix
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 186 186

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek.cluster.nodeid"``

   The node_id topic prefix to use.

Events
######
.. zeek:id:: Cluster::Backend::ZeroMQ::hello
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 372 409

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, id: :zeek:type:`string`)

   Low-level event send to a node in response to their subscription.
   

   :param name: The sending node's name in :zeek:see:`Cluster::nodes`.
   

   :param id: The sending node's identifier, as generated by :zeek:see:`Cluster::node_id`.

.. zeek:id:: Cluster::Backend::ZeroMQ::subscription
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 341 367

   :Type: :zeek:type:`event` (topic: :zeek:type:`string`)

   Low-level event when a subscription is added.
   
   Every node observes all subscriptions from other nodes
   in a cluster through its XPUB socket. Whenever a new
   subscription topic is added, this event is raised with
   the topic.
   

   :param topic: The topic.

.. zeek:id:: Cluster::Backend::ZeroMQ::unsubscription
   :source-code: policy/frameworks/cluster/backend/zeromq/main.zeek 414 433

   :Type: :zeek:type:`event` (topic: :zeek:type:`string`)

   Low-level event when a subscription vanishes.
   
   Every node observes all subscriptions from other nodes
   in a cluster through its XPUB socket. Whenever a subscription
   is removed from the local XPUB socket, this event is raised
   with the topic set to the removed subscription.
   

   :param topic: The topic.


