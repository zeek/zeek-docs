:orphan:

Package: policy/frameworks/cluster/backend/zeromq
=================================================


:doc:`/scripts/policy/frameworks/cluster/backend/zeromq/__load__.zeek`


:doc:`/scripts/policy/frameworks/cluster/backend/zeromq/main.zeek`

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

:doc:`/scripts/policy/frameworks/cluster/backend/zeromq/connect.zeek`

   Establish ZeroMQ connectivity with the broker.

