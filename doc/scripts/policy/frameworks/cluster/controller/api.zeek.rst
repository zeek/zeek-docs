:tocdepth: 3

policy/frameworks/cluster/controller/api.zeek
=============================================
.. zeek:namespace:: ClusterController::API

The event API of cluster controllers. Most endpoints consist of event pairs,
where the controller answers a zeek-client request event with a
corresponding response event. Such event pairs share the same name prefix
and end in "_request" and "_response", respectively.

:Namespace: ClusterController::API
:Imports: :doc:`policy/frameworks/cluster/controller/types.zeek </scripts/policy/frameworks/cluster/controller/types.zeek>`

Summary
~~~~~~~
Constants
#########
============================================================== ================================================================
:zeek:id:`ClusterController::API::version`: :zeek:type:`count` A simple versioning scheme, used to track basic compatibility of
                                                               controller, agents, and zeek-client.
============================================================== ================================================================

Events
######
================================================================================= ======================================================================
:zeek:id:`ClusterController::API::get_instances_request`: :zeek:type:`event`      zeek-client sends this event to request a list of the currently
                                                                                  peered agents/instances.
:zeek:id:`ClusterController::API::get_instances_response`: :zeek:type:`event`     Response to a get_instances_request event.
:zeek:id:`ClusterController::API::notify_agents_ready`: :zeek:type:`event`        The controller triggers this event when the operational cluster
                                                                                  instances align with the ones desired by the cluster
                                                                                  configuration.
:zeek:id:`ClusterController::API::set_configuration_request`: :zeek:type:`event`  zeek-client sends this event to establish a new cluster configuration,
                                                                                  including the full cluster topology.
:zeek:id:`ClusterController::API::set_configuration_response`: :zeek:type:`event` Response to a set_configuration_request event.
:zeek:id:`ClusterController::API::test_timeout_request`: :zeek:type:`event`       This event causes no further action (other than getting logged) if
                                                                                  with_state is F.
:zeek:id:`ClusterController::API::test_timeout_response`: :zeek:type:`event`      Response to a test_timeout_request event.
================================================================================= ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: ClusterController::API::version
   :source-code: policy/frameworks/cluster/controller/api.zeek 13 13

   :Type: :zeek:type:`count`
   :Default: ``1``

   A simple versioning scheme, used to track basic compatibility of
   controller, agents, and zeek-client.

Events
######
.. zeek:id:: ClusterController::API::get_instances_request
   :source-code: policy/frameworks/cluster/controller/main.zeek 462 477

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)

   zeek-client sends this event to request a list of the currently
   peered agents/instances.
   

   :reqid: a request identifier string, echoed in the response event.
   

.. zeek:id:: ClusterController::API::get_instances_response
   :source-code: policy/frameworks/cluster/controller/api.zeek 31 31

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::Result`)

   Response to a get_instances_request event. The controller sends
   this back to the client.
   

   :reqid: the request identifier used in the request event.
   

   :result: the result record. Its data member is a
       :zeek:see:`ClusterController::Types::Instance` record.
   

.. zeek:id:: ClusterController::API::notify_agents_ready
   :source-code: policy/frameworks/cluster/controller/main.zeek 177 195

   :Type: :zeek:type:`event` (instances: :zeek:type:`set` [:zeek:type:`string`])

   The controller triggers this event when the operational cluster
   instances align with the ones desired by the cluster
   configuration. It's essentially a cluster management readiness
   event. This event is currently only used by the controller and not
   published to other topics.
   

   :instances: the set of instance names now ready.
   

.. zeek:id:: ClusterController::API::set_configuration_request
   :source-code: policy/frameworks/cluster/controller/main.zeek 351 461

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, config: :zeek:type:`ClusterController::Types::Configuration`)

   zeek-client sends this event to establish a new cluster configuration,
   including the full cluster topology. The controller processes the update
   and relays it to the agents. Once each has responded (or a timeout occurs)
   the controller sends a corresponding response event back to the client.
   

   :reqid: a request identifier string, echoed in the response event.
   

   :config: a :zeek:see:`ClusterController::Types::Configuration` record
       specifying the cluster configuration.
   

.. zeek:id:: ClusterController::API::set_configuration_response
   :source-code: policy/frameworks/cluster/controller/api.zeek 56 56

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::ResultVec`)

   Response to a set_configuration_request event. The controller sends
   this back to the client.
   

   :reqid: the request identifier used in the request event.
   

   :result: a vector of :zeek:see:`ClusterController::Types::Result` records.
       Each member captures one agent's response.
   

.. zeek:id:: ClusterController::API::test_timeout_request
   :source-code: policy/frameworks/cluster/controller/main.zeek 512 523

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, with_state: :zeek:type:`bool`)

   This event causes no further action (other than getting logged) if
   with_state is F. When T, the controller establishes request state, and
   the controller only ever sends the response event when this state times
   out.
   

   :reqid: a request identifier string, echoed in the response event when
       with_state is T.
   

   :with_state: flag indicating whether the controller should keep (and
       time out) request state for this request.
   

.. zeek:id:: ClusterController::API::test_timeout_response
   :source-code: policy/frameworks/cluster/controller/api.zeek 81 81

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::Result`)

   Response to a test_timeout_request event. The controller sends this
   back to the client if the original request had the with_state flag.
   

   :reqid: the request identifier used in the request event.
   


