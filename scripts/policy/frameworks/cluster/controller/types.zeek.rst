:tocdepth: 3

policy/frameworks/cluster/controller/types.zeek
===============================================
.. zeek:namespace:: ClusterController::Types


:Namespace: ClusterController::Types

Summary
~~~~~~~
Types
#####
========================================================================= ==========================================================
:zeek:type:`ClusterController::Types::Configuration`: :zeek:type:`record` 
:zeek:type:`ClusterController::Types::Instance`: :zeek:type:`record`      Configuration describing a Zeek instance running a Cluster
                                                                          Agent.
:zeek:type:`ClusterController::Types::Node`: :zeek:type:`record`          Configuration describing a Cluster Node process.
:zeek:type:`ClusterController::Types::Option`: :zeek:type:`record`        A Zeek-side option with value.
:zeek:type:`ClusterController::Types::Result`: :zeek:type:`record`        
:zeek:type:`ClusterController::Types::ResultVec`: :zeek:type:`vector`     
:zeek:type:`ClusterController::Types::Role`: :zeek:type:`enum`            Management infrastructure node type.
:zeek:type:`ClusterController::Types::State`: :zeek:type:`enum`           State that a Cluster Node can be in.
========================================================================= ==========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: ClusterController::Types::Configuration
   :source-code: policy/frameworks/cluster/controller/types.zeek 58 67

   :Type: :zeek:type:`record`

      id: :zeek:type:`string` :zeek:attr:`&default` = ``Chd8EgFWk2j`` :zeek:attr:`&optional`

      instances: :zeek:type:`set` [:zeek:type:`ClusterController::Types::Instance`]
         The instances in the cluster.
         XXX we may be able to make this optional

      nodes: :zeek:type:`set` [:zeek:type:`ClusterController::Types::Node`]
         The set of nodes in the cluster, as distributed over the instances.


.. zeek:type:: ClusterController::Types::Instance
   :source-code: policy/frameworks/cluster/controller/types.zeek 24 31

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`

      host: :zeek:type:`addr`

      listen_port: :zeek:type:`port` :zeek:attr:`&optional`

   Configuration describing a Zeek instance running a Cluster
   Agent. Normally, there'll be one instance per cluster
   system: a single physical system.

.. zeek:type:: ClusterController::Types::Node
   :source-code: policy/frameworks/cluster/controller/types.zeek 44 55

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`

      instance: :zeek:type:`string`

      p: :zeek:type:`port`

      role: :zeek:type:`Supervisor::ClusterRole`

      state: :zeek:type:`ClusterController::Types::State`

      scripts: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional`

      options: :zeek:type:`set` [:zeek:type:`ClusterController::Types::Option`] :zeek:attr:`&optional`

      interface: :zeek:type:`string` :zeek:attr:`&optional`

      cpu_affinity: :zeek:type:`int` :zeek:attr:`&optional`

      env: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`

   Configuration describing a Cluster Node process.

.. zeek:type:: ClusterController::Types::Option
   :source-code: policy/frameworks/cluster/controller/types.zeek 16 19

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`

      value: :zeek:type:`string`

   A Zeek-side option with value.

.. zeek:type:: ClusterController::Types::Result
   :source-code: policy/frameworks/cluster/controller/types.zeek 70 77

   :Type: :zeek:type:`record`

      reqid: :zeek:type:`string`

      instance: :zeek:type:`string`

      success: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`

      data: :zeek:type:`any` :zeek:attr:`&optional`

      error: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`

      node: :zeek:type:`string` :zeek:attr:`&optional`


.. zeek:type:: ClusterController::Types::ResultVec
   :source-code: policy/frameworks/cluster/controller/types.zeek 79 79

   :Type: :zeek:type:`vector` of :zeek:type:`ClusterController::Types::Result`


.. zeek:type:: ClusterController::Types::Role
   :source-code: policy/frameworks/cluster/controller/types.zeek 9 14

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ClusterController::Types::NONE ClusterController::Types::Role

      .. zeek:enum:: ClusterController::Types::AGENT ClusterController::Types::Role

      .. zeek:enum:: ClusterController::Types::CONTROLLER ClusterController::Types::Role

   Management infrastructure node type. This intentionally does not
   include the data cluster node types (worker, logger, etc) -- those
   continue to be managed by the cluster framework.

.. zeek:type:: ClusterController::Types::State
   :source-code: policy/frameworks/cluster/controller/types.zeek 35 42

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ClusterController::Types::Running ClusterController::Types::State

      .. zeek:enum:: ClusterController::Types::Stopped ClusterController::Types::State

      .. zeek:enum:: ClusterController::Types::Failed ClusterController::Types::State

      .. zeek:enum:: ClusterController::Types::Crashed ClusterController::Types::State

      .. zeek:enum:: ClusterController::Types::Unknown ClusterController::Types::State

   State that a Cluster Node can be in. State changes trigger an
   API notification (see notify_change()).


