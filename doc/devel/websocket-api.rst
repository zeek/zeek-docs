.. _websocket-api:


======================================
Interacting with Zeek using WebSockets
======================================

Introduction
============

Usually, Zeek produces protocol logs consumed by external applications. These
external applications might be SIEMs, real-time streaming analysis platforms
or basic archival processes compressing logs for long term storage.

Certain use-cases require interacting and influencing Zeek's runtime behavior
outside of static configuration via ``local.zeek``.

The classic :ref:`framework-input` and :ref:`framework-configuration` can be
leveraged for runtime configuration of Zeek as well as triggering arbitrary
events or script execution via option handlers. These frameworks are mostly
file- or process-based and may feel a bit unusual in environments where creation
of files is uncommon or even impossible due to separation of concerns. In many
of today's environments, interacting using HTTP-based APIs or other remote
interfaces is more common.

.. note::

    As an aside, if you need more flexibility than the WebSocket API offers today,
    an alternative could be to use :ref:`javascript` within Zeek. This opens the
    possibility to run a separate HTTP or a totally different Node.js based server
    within a Zeek process for quick experimentation and evaluation of other
    approaches.

Background and Setup
====================

Since Zeek 5.0, Zeek allows connections from external clients over WebSocket.
This allows these clients to interact with Zeek's publish-subscribe layer and
exchange Zeek events with other Zeek nodes.
Initially, this implementation resided in the Broker subsystem.
With Zeek 8.0, most of the implementation has been moved into core Zeek
itself with the v1 serialization format remaining in Broker.

WebSocket clients may subscribe to a fixed set of topics and will receive
Zeek events matching these topics that Zeek cluster nodes, but also other
WebSocket clients, publish.

With Zeek 8.0, Zeekctl has received support to interact with Zeek cluster nodes
using the WebSocket protocol. If you're running a Zeekctl based cluster and
want to experiment with WebSocket functionality, add ``UseWebSocket = 1`` to
your ``zeekctl.cfg``:

.. code-block:: ini

    # zeekctl.cfg
    ...
    UseWebSocket = 1

This will essentially add the following snippet, enabling a WebSocket server
on the Zeek manager:

.. code-block:: zeek
   :caption: websocket.zeek

   event zeek_init()
        {
        if ( Cluster::local_node_type() == Cluster::MANAGER )
            {
            Cluster::listen_websocket([
                $listen_addr=127.0.0.1,
                $listen_port=27759/tcp,
            ]);
            }
        }


To verify that the WebSocket API is functional in your deployment use, for example,
`websocat <https://github.com/vi/websocat>`_ as a quick check.

.. code-block:: shell

   $ echo '[]' | websocat ws://127.0.0.1:27759/v1/messages/json
   {"type":"ack","endpoint":"3eece35d-9f94-568d-861c-6a16c433e090-websocket-2","version":"8.0.0-dev.684"}

Zeek's ``cluster.log`` file will also have an entry for the WebSocket client connection.
The empty array in the command specifies the client's subscriptions, in this case none.

Version 1
=========

The currently implemented protocol is accessible at ``/v1/messages/json``.
The `data representation <https://docs.zeek.org/projects/broker/en/current/web-socket.html#data-representation>`_
is documented in detail within the Broker project. Note that this format is a
direct translation of Broker's binary format into JSON, resulting in a fairly
tight coupling between WebSocket clients and the corresponding Zeek scripts.
Most prominently is the representation of record values as vectors instead
of objects, making the protocol sensitive against reordering or introduction
of optional fields to records.

.. note::

   We're looking into an iteration of the format. If you have feedback or
   would like to contribute, please reach out on the usual community channels.


Handshake and Acknowledgement
-----------------------------

The first message after a WebSocket connection has been established originates
from the client. This message is a JSON array of strings that represent the
topics the WebSocket client wishes to subscribe to.

Zeek replies with an acknowledgement message that's a JSON object or an error.

Events
------

After the acknowledgement, WebSocket clients receive all events arriving on
topics they have subscribed to.

.. code-block:: shell

   $ websocat ws://127.0.0.1:27759/v1/messages/json
   ["zeek.test"]
   {"type":"ack","endpoint":"d955d990-ad8a-5ed4-8bc5-bee252d4a2e6-websocket-0","version":"8.0.0-dev.684"}
   {"type":"data-message","topic":"zeek.test","@data-type":"vector","data":[{"@data-type":"count","data":1},{"@data-type":"count","data":1},{"@data-type":"vector","data":[{"@data-type":"string","data":"hello"},{"@data-type":"vector","data":[{"@data-type":"count","data":3}]},{"@data-type":"vector","data":[]}]}]}

The received messages, again, are encoded in Broker's JSON format. Above ``data-message``
represents an event received on topic ``zeek.test``. The event's name is ``hello``.
This event has a single argument of type :zeek:type:`count`. In the example above
its value is ``3``.

To send events, WebSocket clients similarly encode their event representation
to Broker's JSON format and send them as `text data frames <https://datatracker.ietf.org/doc/html/rfc6455#section-5.6>`_.


Language Bindings
-----------------

Note that it's possible to use any language that offers WebSocket bindings.
The ones listed below mostly add a bit of convenience features around the
initial Handshake message, error handling and serializing Zeek events and
values into the Broker-specific serialization format.

For example, using the Node.js `builtin WebSocket functionality <https://nodejs.org/en/learn/getting-started/websocket>`_,
the ``websocat`` example from above can be reproduced as follows:

.. code-block:: javascript
   :caption: client.js

   // client.js
   const socket = new WebSocket('ws://192.168.122.107:27759/v1/messages/json');

   socket.addEventListener('open', event => {
     socket.send('["zeek.test"]');
   });

   socket.addEventListener('message', event => {
     console.log('Message from server: ', event.data);
   });

.. code-block:: shell

   $ node ./client.js
   Message from server:  {"type":"ack","endpoint":"2e951b0c-3ca4-504c-ae8a-5d3750fec588-websocket-10","version":"8.0.0-dev.684"}
   Message from server:  {"type":"data-message","topic":"zeek.test","@data-type":"vector","data":[{"@data-type":"count","data":1},{"@data-type":"count","data":1},{"@data-type":"vector","data":[{"@data-type":"string","data":"hello"},{"@data-type":"vector","data":[{"@data-type":"count","data":374}]},{"@data-type":"vector","data":[]}]}]}


Golang
^^^^^^

* `Zeek Broker websocket interface library for Golang <https://github.com/corelight/go-zeek-broker-ws>`_ (not an official Zeek project)


Rust
^^^^

* `Rust types for interacting with Zeek over WebSocket <https://github.com/bbannier/zeek-websocket-rs>`_ (not an official Zeek project)

Python
^^^^^^

There are no ready to use Python libraries available, but the third-party
`websockets <https://github.com/python-websockets/websockets>`_ package
allows to get started quickly.
You may take inspiration from `zeek-client's implementation <https://github.com/zeek/zeek-client>`_
or the `small helper library <https://raw.githubusercontent.com/zeek/zeek/refs/heads/master/testing/btest/Files/ws/wstest.py>`_ used by various of Zeek's own tests for the
WebSocket API.
Zeekctl similarly ships a `light implementation <https://github.com/zeek/zeekctl/blob/93459b37c3deab4bec9e886211672024fa3e4759/ZeekControl/events.py#L159>`_
using the ``websockets`` library to implement its ``netstats`` and ``print`` commands.
