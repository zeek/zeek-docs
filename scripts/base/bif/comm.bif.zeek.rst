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
=================================================== ==========================================================
:zeek:id:`Broker::error`: :zeek:type:`event`        Generated when an error occurs in the Broker sub-system.
:zeek:id:`Broker::peer_added`: :zeek:type:`event`   Generated when a new peering has been established.
:zeek:id:`Broker::peer_lost`: :zeek:type:`event`    Generated when an existing peering has been lost.
:zeek:id:`Broker::peer_removed`: :zeek:type:`event` Generated when an existing peer has been removed.
:zeek:id:`Broker::status`: :zeek:type:`event`       Generated when something changes in the Broker sub-system.
=================================================== ==========================================================

Functions
#########
============================================================================ =
:zeek:id:`Broker::__listen`: :zeek:type:`function`                           
:zeek:id:`Broker::__node_id`: :zeek:type:`function`                          
:zeek:id:`Broker::__peer`: :zeek:type:`function`                             
:zeek:id:`Broker::__peers`: :zeek:type:`function`                            
:zeek:id:`Broker::__set_metrics_export_endpoint_name`: :zeek:type:`function` 
:zeek:id:`Broker::__set_metrics_export_interval`: :zeek:type:`function`      
:zeek:id:`Broker::__set_metrics_export_prefixes`: :zeek:type:`function`      
:zeek:id:`Broker::__set_metrics_export_topic`: :zeek:type:`function`         
:zeek:id:`Broker::__unpeer`: :zeek:type:`function`                           
============================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: Broker::error
   :source-code: base/frameworks/broker/log.zeek 71 84

   :Type: :zeek:type:`event` (code: :zeek:type:`Broker::ErrorCode`, msg: :zeek:type:`string`)

   Generated when an error occurs in the Broker sub-system.

.. zeek:id:: Broker::peer_added
   :source-code: base/bif/comm.bif.zeek 17 17

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when a new peering has been established.

.. zeek:id:: Broker::peer_lost
   :source-code: base/bif/comm.bif.zeek 25 25

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when an existing peering has been lost.

.. zeek:id:: Broker::peer_removed
   :source-code: base/frameworks/broker/log.zeek 61 64

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when an existing peer has been removed.

.. zeek:id:: Broker::status
   :source-code: base/bif/comm.bif.zeek 13 13

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when something changes in the Broker sub-system.

Functions
#########
.. zeek:id:: Broker::__listen
   :source-code: base/bif/comm.bif.zeek 69 69

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`port`


.. zeek:id:: Broker::__node_id
   :source-code: base/bif/comm.bif.zeek 81 81

   :Type: :zeek:type:`function` () : :zeek:type:`string`


.. zeek:id:: Broker::__peer
   :source-code: base/bif/comm.bif.zeek 72 72

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`, retry: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__peers
   :source-code: base/bif/comm.bif.zeek 78 78

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::PeerInfos`


.. zeek:id:: Broker::__set_metrics_export_endpoint_name
   :source-code: base/bif/comm.bif.zeek 90 90

   :Type: :zeek:type:`function` (value: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_metrics_export_interval
   :source-code: base/bif/comm.bif.zeek 84 84

   :Type: :zeek:type:`function` (value: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_metrics_export_prefixes
   :source-code: base/bif/comm.bif.zeek 93 93

   :Type: :zeek:type:`function` (filter: :zeek:type:`string_vec`) : :zeek:type:`bool`


.. zeek:id:: Broker::__set_metrics_export_topic
   :source-code: base/bif/comm.bif.zeek 87 87

   :Type: :zeek:type:`function` (value: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Broker::__unpeer
   :source-code: base/bif/comm.bif.zeek 75 75

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`bool`



