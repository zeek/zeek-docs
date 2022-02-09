:tocdepth: 3

policy/frameworks/cluster/agent/api.zeek
========================================
.. zeek:namespace:: ClusterAgent::API

The event API of cluster agents. Most endpoints consist of event pairs,
where the agent answers a request event with a corresponding response
event. Such event pairs share the same name prefix and end in "_request" and
"_response", respectively.

:Namespace: ClusterAgent::API
:Imports: :doc:`base/frameworks/supervisor/control.zeek </scripts/base/frameworks/supervisor/control.zeek>`, :doc:`policy/frameworks/cluster/controller/types.zeek </scripts/policy/frameworks/cluster/controller/types.zeek>`

Summary
~~~~~~~
Constants
#########
========================================================= ================================================================
:zeek:id:`ClusterAgent::API::version`: :zeek:type:`count` A simple versioning scheme, used to track basic compatibility of
                                                          controller and agent.
========================================================= ================================================================

Events
######
============================================================================ =====================================================================
:zeek:id:`ClusterAgent::API::agent_standby_request`: :zeek:type:`event`      The controller sends this event to convey that the agent is not
                                                                             currently required.
:zeek:id:`ClusterAgent::API::agent_standby_response`: :zeek:type:`event`     Response to an agent_standby_request event.
:zeek:id:`ClusterAgent::API::agent_welcome_request`: :zeek:type:`event`      The controller sends this event to confirm to the agent that it is
                                                                             part of the current cluster topology.
:zeek:id:`ClusterAgent::API::agent_welcome_response`: :zeek:type:`event`     Response to an agent_welcome_request event.
:zeek:id:`ClusterAgent::API::get_nodes_request`: :zeek:type:`event`          The controller sends this event to request a list of
                                                                             :zeek:see:`ClusterController::Types::NodeStatus` records that capture
                                                                             the status of Supervisor-managed nodes running on this instance.
:zeek:id:`ClusterAgent::API::get_nodes_response`: :zeek:type:`event`         Response to a get_nodes_request event.
:zeek:id:`ClusterAgent::API::notify_agent_hello`: :zeek:type:`event`         The agent sends this event upon peering as a "check-in", informing
                                                                             the controller that an agent of the given name is now available to
                                                                             communicate with.
:zeek:id:`ClusterAgent::API::notify_change`: :zeek:type:`event`              
:zeek:id:`ClusterAgent::API::notify_error`: :zeek:type:`event`               
:zeek:id:`ClusterAgent::API::notify_log`: :zeek:type:`event`                 
:zeek:id:`ClusterAgent::API::set_configuration_request`: :zeek:type:`event`  The controller sends this event to convey a new cluster configuration
                                                                             to the agent.
:zeek:id:`ClusterAgent::API::set_configuration_response`: :zeek:type:`event` Response to a set_configuration_request event.
============================================================================ =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: ClusterAgent::API::version
   :source-code: policy/frameworks/cluster/agent/api.zeek 14 14

   :Type: :zeek:type:`count`
   :Default: ``1``

   A simple versioning scheme, used to track basic compatibility of
   controller and agent.

Events
######
.. zeek:id:: ClusterAgent::API::agent_standby_request
   :source-code: policy/frameworks/cluster/agent/main.zeek 295 313

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)

   The controller sends this event to convey that the agent is not
   currently required. This status may later change, depending on
   updates from the client, so the Broker-level peering can remain
   active. The agent releases any cluster-related resources (including
   shutdown of existing Zeek cluster nodes) when processing the request,
   and confirms via the response event. Shutting down an agent at this
   point has no operational impact on the running cluster.
   

   :reqid: a request identifier string, echoed in the response event.
   

.. zeek:id:: ClusterAgent::API::agent_standby_response
   :source-code: policy/frameworks/cluster/agent/api.zeek 104 104

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::Result`)

   Response to an agent_standby_request event. The agent sends this
   back to the controller.
   

   :reqid: the request identifier used in the request event.
   

   :result: the result record.
   

.. zeek:id:: ClusterAgent::API::agent_welcome_request
   :source-code: policy/frameworks/cluster/agent/main.zeek 282 293

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)

   The controller sends this event to confirm to the agent that it is
   part of the current cluster topology. The agent acknowledges with the
   corresponding response event.
   

   :reqid: a request identifier string, echoed in the response event.
   

.. zeek:id:: ClusterAgent::API::agent_welcome_response
   :source-code: policy/frameworks/cluster/controller/main.zeek 263 290

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::Result`)

   Response to an agent_welcome_request event. The agent sends this
   back to the controller.
   

   :reqid: the request identifier used in the request event.
   

   :result: the result record.
   

.. zeek:id:: ClusterAgent::API::get_nodes_request
   :source-code: policy/frameworks/cluster/agent/main.zeek 271 280

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)

   The controller sends this event to request a list of
   :zeek:see:`ClusterController::Types::NodeStatus` records that capture
   the status of Supervisor-managed nodes running on this instance.
   instances.
   

   :reqid: a request identifier string, echoed in the response event.
   

.. zeek:id:: ClusterAgent::API::get_nodes_response
   :source-code: policy/frameworks/cluster/controller/main.zeek 478 521

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::Result`)

   Response to a get_nodes_request event. The agent sends this back to the
   controller.
   

   :reqid: the request identifier used in the request event.
   

   :result: a :zeek:see:`ClusterController::Types::Result` record. Its data
       member is a vector of :zeek:see:`ClusterController::Types::NodeStatus`
       records, covering the nodes at this instance. The result may also
       indicate failure, with error messages indicating what went wrong.
   

.. zeek:id:: ClusterAgent::API::notify_agent_hello
   :source-code: policy/frameworks/cluster/controller/main.zeek 229 261

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, host: :zeek:type:`addr`, api_version: :zeek:type:`count`)

   The agent sends this event upon peering as a "check-in", informing
   the controller that an agent of the given name is now available to
   communicate with. It is a controller-level equivalent of
   `:zeek:see:`Broker::peer_added`.
   

   :instance: an instance name, really the agent's name as per :zeek:see:`ClusterAgent::name`.
   

   :host: the IP address of the agent. (This may change in the future.)
   

   :api_version: the API version of this agent.
   

.. zeek:id:: ClusterAgent::API::notify_change
   :source-code: policy/frameworks/cluster/controller/main.zeek 294 295

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, n: :zeek:type:`ClusterController::Types::Node`, old: :zeek:type:`ClusterController::Types::State`, new: :zeek:type:`ClusterController::Types::State`)


.. zeek:id:: ClusterAgent::API::notify_error
   :source-code: policy/frameworks/cluster/controller/main.zeek 299 300

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, msg: :zeek:type:`string`, node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)


.. zeek:id:: ClusterAgent::API::notify_log
   :source-code: policy/frameworks/cluster/controller/main.zeek 304 305

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, msg: :zeek:type:`string`, node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)


.. zeek:id:: ClusterAgent::API::set_configuration_request
   :source-code: policy/frameworks/cluster/agent/main.zeek 99 193

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, config: :zeek:type:`ClusterController::Types::Configuration`)

   The controller sends this event to convey a new cluster configuration
   to the agent. Once processed, the agent responds with the response
   event.
   

   :reqid: a request identifier string, echoed in the response event.
   

   :config: a :zeek:see:`ClusterController::Types::Configuration` record
       describing the cluster topology. Note that this contains the full
       topology, not just the part pertaining to this agent. That's because
       the cluster framework requires full cluster visibility to establish
       the needed peerings.
   

.. zeek:id:: ClusterAgent::API::set_configuration_response
   :source-code: policy/frameworks/cluster/controller/main.zeek 309 349

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::Result`)

   Response to a set_configuration_request event. The agent sends
   this back to the controller.
   

   :reqid: the request identifier used in the request event.
   

   :result: the result record.
   


