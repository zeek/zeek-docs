:tocdepth: 3

policy/frameworks/cluster/controller/types.zeek
===============================================
.. zeek:namespace:: ClusterController::Types

This module holds the basic types needed for the Cluster Controller
framework. These are used by both agent and controller, and several
have corresponding equals in the zeek-client implementation.

:Namespace: ClusterController::Types

Summary
~~~~~~~
Types
#####
========================================================================= =====================================================================
:zeek:type:`ClusterController::Types::Configuration`: :zeek:type:`record` Data structure capturing a cluster's complete configuration.
:zeek:type:`ClusterController::Types::Instance`: :zeek:type:`record`      Configuration describing a Zeek instance running a Cluster
                                                                          Agent.
:zeek:type:`ClusterController::Types::InstanceVec`: :zeek:type:`vector`   
:zeek:type:`ClusterController::Types::Node`: :zeek:type:`record`          Configuration describing a Cluster Node process.
:zeek:type:`ClusterController::Types::NodeStatus`: :zeek:type:`record`    The status of a Supervisor-managed node, as reported to the client in
                                                                          a get_nodes_request/get_nodes_response transaction.
:zeek:type:`ClusterController::Types::NodeStatusVec`: :zeek:type:`vector` 
:zeek:type:`ClusterController::Types::Option`: :zeek:type:`record`        A Zeek-side option with value.
:zeek:type:`ClusterController::Types::Result`: :zeek:type:`record`        Return value for request-response API event pairs
:zeek:type:`ClusterController::Types::ResultVec`: :zeek:type:`vector`     
:zeek:type:`ClusterController::Types::Role`: :zeek:type:`enum`            Management infrastructure node type.
:zeek:type:`ClusterController::Types::State`: :zeek:type:`enum`           State that a Cluster Node can be in.
========================================================================= =====================================================================

Functions
#########
============================================================================ ============================================================
:zeek:id:`ClusterController::Types::result_to_string`: :zeek:type:`function` Given a :zeek:see:`ClusterController::Types::Result` record,
                                                                             this function returns a string summarizing it.
============================================================================ ============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: ClusterController::Types::Configuration
   :source-code: policy/frameworks/cluster/controller/types.zeek 65 72

   :Type: :zeek:type:`record`

      id: :zeek:type:`string` :zeek:attr:`&default` = ``fD0qxAnfwOe`` :zeek:attr:`&optional`
         Unique identifier for a particular configuration

      instances: :zeek:type:`set` [:zeek:type:`ClusterController::Types::Instance`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         The instances in the cluster.

      nodes: :zeek:type:`set` [:zeek:type:`ClusterController::Types::Node`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         The set of nodes in the cluster, as distributed over the instances.

   Data structure capturing a cluster's complete configuration.

.. zeek:type:: ClusterController::Types::Instance
   :source-code: policy/frameworks/cluster/controller/types.zeek 26 33

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         Unique, human-readable instance name

      host: :zeek:type:`addr`
         IP address of system

      listen_port: :zeek:type:`port` :zeek:attr:`&optional`
         Agent listening port. Not needed if agents connect to controller.

   Configuration describing a Zeek instance running a Cluster
   Agent. Normally, there'll be one instance per cluster
   system: a single physical system.

.. zeek:type:: ClusterController::Types::InstanceVec
   :source-code: policy/frameworks/cluster/controller/types.zeek 35 35

   :Type: :zeek:type:`vector` of :zeek:type:`ClusterController::Types::Instance`


.. zeek:type:: ClusterController::Types::Node
   :source-code: policy/frameworks/cluster/controller/types.zeek 51 62

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         Cluster-unique, human-readable node name

      instance: :zeek:type:`string`
         Name of instance where node is to run

      role: :zeek:type:`Supervisor::ClusterRole`
         Role of the node.

      state: :zeek:type:`ClusterController::Types::State`
         Desired, or current, run state.

      p: :zeek:type:`port` :zeek:attr:`&optional`
         Port on which this node will listen

      scripts: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional`
         Additional Zeek scripts for node

      options: :zeek:type:`set` [:zeek:type:`ClusterController::Types::Option`] :zeek:attr:`&optional`
         Zeek options for node

      interface: :zeek:type:`string` :zeek:attr:`&optional`
         Interface to sniff

      cpu_affinity: :zeek:type:`int` :zeek:attr:`&optional`
         CPU/core number to pin to

      env: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Custom environment vars

   Configuration describing a Cluster Node process.

.. zeek:type:: ClusterController::Types::NodeStatus
   :source-code: policy/frameworks/cluster/controller/types.zeek 76 90

   :Type: :zeek:type:`record`

      node: :zeek:type:`string`
         Cluster-unique, human-readable node name

      state: :zeek:type:`ClusterController::Types::State`
         Current run state of the node.

      mgmt_role: :zeek:type:`ClusterController::Types::Role` :zeek:attr:`&default` = ``ClusterController::Types::NONE`` :zeek:attr:`&optional`
         Role the node plays in cluster management.

      cluster_role: :zeek:type:`Supervisor::ClusterRole` :zeek:attr:`&default` = ``Supervisor::NONE`` :zeek:attr:`&optional`
         Role the node plays in the data cluster.

      pid: :zeek:type:`int` :zeek:attr:`&optional`
         Process ID of the node. This is optional because the Supervisor may not have
         a PID when a node is still bootstrapping.

      p: :zeek:type:`port` :zeek:attr:`&optional`
         The node's Broker peering listening port, if any.

   The status of a Supervisor-managed node, as reported to the client in
   a get_nodes_request/get_nodes_response transaction.

.. zeek:type:: ClusterController::Types::NodeStatusVec
   :source-code: policy/frameworks/cluster/controller/types.zeek 92 92

   :Type: :zeek:type:`vector` of :zeek:type:`ClusterController::Types::NodeStatus`


.. zeek:type:: ClusterController::Types::Option
   :source-code: policy/frameworks/cluster/controller/types.zeek 18 21

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         Name of option

      value: :zeek:type:`string`
         Value of option

   A Zeek-side option with value.

.. zeek:type:: ClusterController::Types::Result
   :source-code: policy/frameworks/cluster/controller/types.zeek 95 102

   :Type: :zeek:type:`record`

      reqid: :zeek:type:`string`
         Request ID of operation this result refers to

      instance: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         Name of associated instance (for context)

      success: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         True if successful

      data: :zeek:type:`any` :zeek:attr:`&optional`
         Addl data returned for successful operation

      error: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         Descriptive error on failure

      node: :zeek:type:`string` :zeek:attr:`&optional`
         Name of associated node (for context)

   Return value for request-response API event pairs

.. zeek:type:: ClusterController::Types::ResultVec
   :source-code: policy/frameworks/cluster/controller/types.zeek 104 104

   :Type: :zeek:type:`vector` of :zeek:type:`ClusterController::Types::Result`


.. zeek:type:: ClusterController::Types::Role
   :source-code: policy/frameworks/cluster/controller/types.zeek 11 16

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ClusterController::Types::NONE ClusterController::Types::Role

         No active role in cluster management

      .. zeek:enum:: ClusterController::Types::AGENT ClusterController::Types::Role

         A cluster management agent.

      .. zeek:enum:: ClusterController::Types::CONTROLLER ClusterController::Types::Role

         The cluster's controller.

   Management infrastructure node type. This intentionally does not
   include the data cluster node types (worker, logger, etc) -- those
   continue to be managed by the cluster framework.

.. zeek:type:: ClusterController::Types::State
   :source-code: policy/frameworks/cluster/controller/types.zeek 41 49

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ClusterController::Types::PENDING ClusterController::Types::State

         Not yet running

      .. zeek:enum:: ClusterController::Types::RUNNING ClusterController::Types::State

         Running and operating normally

      .. zeek:enum:: ClusterController::Types::STOPPED ClusterController::Types::State

         Explicitly stopped

      .. zeek:enum:: ClusterController::Types::FAILED ClusterController::Types::State

         Failed to start; and permanently halted

      .. zeek:enum:: ClusterController::Types::CRASHED ClusterController::Types::State

         Crashed, will be restarted,

      .. zeek:enum:: ClusterController::Types::UNKNOWN ClusterController::Types::State

         State not known currently (e.g., because of lost connectivity)

   State that a Cluster Node can be in. State changes trigger an
   API notification (see notify_change()). The Pending state corresponds
   to the Supervisor not yet reporting a PID for a node when it has not
   yet fully launched.

Functions
#########
.. zeek:id:: ClusterController::Types::result_to_string
   :source-code: policy/frameworks/cluster/controller/types.zeek 111 136

   :Type: :zeek:type:`function` (res: :zeek:type:`ClusterController::Types::Result`) : :zeek:type:`string`

   Given a :zeek:see:`ClusterController::Types::Result` record,
   this function returns a string summarizing it.


