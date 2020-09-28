:tocdepth: 3

base/bif/comm.bif.zeek
======================
.. zeek:namespace:: Broker
.. zeek:namespace:: GLOBAL

Functions and events regarding broker communication mechanisms.

:Namespaces: Broker, GLOBAL

Summary
~~~~~~~
Events
######
=========================================================== ================================================================
:zeek:id:`Broker::error`: :zeek:type:`event`                Generated when an error occurs in the Broker sub-system.
:zeek:id:`Broker::endpoint_discovered`: :zeek:type:`event`  Generated when a new Broker endpoint appeared.
:zeek:id:`Broker::peer_added`: :zeek:type:`event`           Generated when a new peering has been established.
:zeek:id:`Broker::peer_lost`: :zeek:type:`event`            Generated when an existing peering has been lost.
:zeek:id:`Broker::peer_removed`: :zeek:type:`event`         Generated when an existing peer has been removed.
:zeek:id:`Broker::endpoint_unreachable`: :zeek:type:`event` Generated when the last path to a Broker endpoint has been lost.
:zeek:id:`Broker::status`: :zeek:type:`event`               Generated when something changes in the Broker sub-system.
=========================================================== ================================================================

Functions
#########
=================================================== =
:zeek:id:`Broker::__listen`: :zeek:type:`function`
:zeek:id:`Broker::__node_id`: :zeek:type:`function`
:zeek:id:`Broker::__peer`: :zeek:type:`function`
:zeek:id:`Broker::__peers`: :zeek:type:`function`
:zeek:id:`Broker::__unpeer`: :zeek:type:`function`
=================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: Broker::error

   :Type: :zeek:type:`event` (code: :zeek:type:`Broker::ErrorCode`, msg: :zeek:type:`string`)

   Generated when an error occurs in the Broker sub-system.

.. zeek:id:: Broker::endpoint_discovered

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when a new Broker endpoint appeared. This may occur either after
   establishing new network connections via ``Broker::peer`` or after learning
   paths to new Broker endpoints through other peers.

.. zeek:id:: Broker::peer_added

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when a new peering has been established. A Broker peer is reachable
   in one hop via a direct network connection between two Broker endpoints.

.. zeek:id:: Broker::peer_lost

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when an existing peering has been lost, i.e., after losing the
   network connection to it. Note that this endpoint may still remain reachable
   until observing the ``endpoint_unreachable`` event.

.. zeek:id:: Broker::peer_removed

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when an existing peer has been removed gracefully.

.. zeek:id:: Broker::endpoint_unreachable

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated after losing the last known path to a Broker endpoint.

.. zeek:id:: Broker::status

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when something changes in the Broker sub-system.

Functions
#########
.. zeek:id:: Broker::__listen

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`port`


.. zeek:id:: Broker::__node_id

   :Type: :zeek:type:`function` () : :zeek:type:`string`


.. zeek:id:: Broker::__peer

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`, retry: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__peers

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::PeerInfos`


.. zeek:id:: Broker::__unpeer

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`bool`



