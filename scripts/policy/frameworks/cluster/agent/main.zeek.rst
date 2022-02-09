:tocdepth: 3

policy/frameworks/cluster/agent/main.zeek
=========================================
.. zeek:namespace:: ClusterAgent::Runtime

This is the main "runtime" of a cluster agent. Zeek does not load this
directly; rather, the agent's bootstrapping module (in ./boot.zeek)
specifies it as the script to run in the node newly created via Zeek's
supervisor.

:Namespace: ClusterAgent::Runtime
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`policy/frameworks/cluster/agent/api.zeek </scripts/policy/frameworks/cluster/agent/api.zeek>`, :doc:`policy/frameworks/cluster/controller/config.zeek </scripts/policy/frameworks/cluster/controller/config.zeek>`, :doc:`policy/frameworks/cluster/controller/log.zeek </scripts/policy/frameworks/cluster/controller/log.zeek>`, :doc:`policy/frameworks/cluster/controller/request.zeek </scripts/policy/frameworks/cluster/controller/request.zeek>`

Summary
~~~~~~~
Types
#####
======================================================================== ==============================================================
:zeek:type:`ClusterAgent::Runtime::SupervisorState`: :zeek:type:`record` Request state specific to the agent's Supervisor interactions.
======================================================================== ==============================================================

Redefinitions
#############
=================================================================================================== ==============================================================================================
:zeek:type:`ClusterController::Request::Request`: :zeek:type:`record`                               
                                                                                                    
                                                                                                    :New Fields: :zeek:type:`ClusterController::Request::Request`
                                                                                                    
                                                                                                      supervisor_state: :zeek:type:`ClusterAgent::Runtime::SupervisorState` :zeek:attr:`&optional`
:zeek:id:`ClusterController::role`: :zeek:type:`ClusterController::Types::Role` :zeek:attr:`&redef` 
=================================================================================================== ==============================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: ClusterAgent::Runtime::SupervisorState
   :source-code: policy/frameworks/cluster/agent/main.zeek 21 23

   :Type: :zeek:type:`record`

      node: :zeek:type:`string`
         Name of the node the Supervisor is acting on.

   Request state specific to the agent's Supervisor interactions.


