:tocdepth: 3

base/bif/cluster.bif.zeek
=========================
.. zeek:namespace:: Cluster
.. zeek:namespace:: GLOBAL


:Namespaces: Cluster, GLOBAL

Summary
~~~~~~~
Functions
#########
========================================================== ===================================================================
:zeek:id:`Cluster::Backend::__init`: :zeek:type:`function` Initialize the global cluster backend.
:zeek:id:`Cluster::__subscribe`: :zeek:type:`function`     
:zeek:id:`Cluster::__unsubscribe`: :zeek:type:`function`   
:zeek:id:`Cluster::make_event`: :zeek:type:`function`      Create a data structure that may be used to send a remote event via
                                                           :zeek:see:`Broker::publish`.
:zeek:id:`Cluster::publish`: :zeek:type:`function`         Publishes an event to a given topic.
:zeek:id:`Cluster::publish_hrw`: :zeek:type:`function`     Publishes an event to a node within a pool according to Rendezvous
                                                           (Highest Random Weight) hashing strategy.
:zeek:id:`Cluster::publish_rr`: :zeek:type:`function`      Publishes an event to a node within a pool according to Round-Robin
                                                           distribution strategy.
========================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Cluster::Backend::__init
   :source-code: base/bif/cluster.bif.zeek 44 44

   :Type: :zeek:type:`function` (nid: :zeek:type:`string`) : :zeek:type:`bool`

   Initialize the global cluster backend.
   

   :returns: true on success.

.. zeek:id:: Cluster::__subscribe
   :source-code: base/bif/cluster.bif.zeek 35 35

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Cluster::__unsubscribe
   :source-code: base/bif/cluster.bif.zeek 38 38

   :Type: :zeek:type:`function` (topic_prefix: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: Cluster::make_event
   :source-code: base/bif/cluster.bif.zeek 32 32

   :Type: :zeek:type:`function` (...) : :zeek:type:`Cluster::Event`

   Create a data structure that may be used to send a remote event via
   :zeek:see:`Broker::publish`.
   

   :param args: an event, followed by a list of argument values that may be used
         to call it.
   

   :returns: A :zeek:type:`Cluster::Event` instance that can be published via
            :zeek:see:`Cluster::publish`, :zeek:see:`Cluster::publish_rr`
            or :zeek:see:`Cluster::publish_hrw`.

.. zeek:id:: Cluster::publish
   :source-code: base/bif/cluster.bif.zeek 20 20

   :Type: :zeek:type:`function` (...) : :zeek:type:`bool`

   Publishes an event to a given topic.
   

   :param topic: a topic associated with the event message.
   

   :param args: Either the event arguments as already made by
         :zeek:see:`Cluster::make_event` or the argument list to pass along
         to it.
   

   :returns: true if the message is sent.

.. zeek:id:: Cluster::publish_hrw
   :source-code: base/bif/cluster.bif.zeek 80 80

   :Type: :zeek:type:`function` (...) : :zeek:type:`bool`

   Publishes an event to a node within a pool according to Rendezvous
   (Highest Random Weight) hashing strategy.
   

   :param pool: the pool of nodes that are eligible to receive the event.
   

   :param key: data used for input to the hashing function that will uniformly
        distribute keys among available nodes.
   

   :param args: Either the event arguments as already made by
         :zeek:see:`Broker::make_event` or the argument list to pass along
         to it.
   

   :returns: true if the message is sent.

.. zeek:id:: Cluster::publish_rr
   :source-code: base/bif/cluster.bif.zeek 63 63

   :Type: :zeek:type:`function` (...) : :zeek:type:`bool`

   Publishes an event to a node within a pool according to Round-Robin
   distribution strategy.
   

   :param pool: the pool of nodes that are eligible to receive the event.
   

   :param key: an arbitrary string to identify the purpose for which you're
        distributing the event.  e.g. consider using namespacing of your
        script like "Intel::cluster_rr_key".
   

   :param args: Either the event arguments as already made by
         :zeek:see:`Cluster::make_event` or the argument list to pass along
         to it.
   

   :returns: true if the message is sent.


