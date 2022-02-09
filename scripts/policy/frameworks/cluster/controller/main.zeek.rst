:tocdepth: 3

policy/frameworks/cluster/controller/main.zeek
==============================================
.. zeek:namespace:: ClusterController::Runtime

This is the main "runtime" of the cluster controller. Zeek does not load
this directly; rather, the controller's bootstrapping module (in ./boot.zeek)
specifies it as the script to run in the node newly created via Zeek's
supervisor.

:Namespace: ClusterController::Runtime
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`policy/frameworks/cluster/agent/api.zeek </scripts/policy/frameworks/cluster/agent/api.zeek>`, :doc:`policy/frameworks/cluster/agent/config.zeek </scripts/policy/frameworks/cluster/agent/config.zeek>`, :doc:`policy/frameworks/cluster/controller/api.zeek </scripts/policy/frameworks/cluster/controller/api.zeek>`, :doc:`policy/frameworks/cluster/controller/log.zeek </scripts/policy/frameworks/cluster/controller/log.zeek>`, :doc:`policy/frameworks/cluster/controller/request.zeek </scripts/policy/frameworks/cluster/controller/request.zeek>`, :doc:`policy/frameworks/cluster/controller/util.zeek </scripts/policy/frameworks/cluster/controller/util.zeek>`

Summary
~~~~~~~
Types
#####
=================================================================================== =================================================================
:zeek:type:`ClusterController::Runtime::GetNodesState`: :zeek:type:`record`         Request state specific to
                                                                                    :zeek:see:`ClusterController::API::get_nodes_request` and
                                                                                    :zeek:see:`ClusterController::API::get_nodes_response`.
:zeek:type:`ClusterController::Runtime::SetConfigurationState`: :zeek:type:`record` Request state specific to
                                                                                    :zeek:see:`ClusterController::API::set_configuration_request` and
                                                                                    :zeek:see:`ClusterController::API::set_configuration_response`.
:zeek:type:`ClusterController::Runtime::TestState`: :zeek:type:`record`             Dummy state for internal state-keeping test cases.
=================================================================================== =================================================================

Redefinitions
#############
=================================================================================================== ================================================================================================================
:zeek:type:`ClusterController::Request::Request`: :zeek:type:`record`                               
                                                                                                    
                                                                                                    :New Fields: :zeek:type:`ClusterController::Request::Request`
                                                                                                    
                                                                                                      set_configuration_state: :zeek:type:`ClusterController::Runtime::SetConfigurationState` :zeek:attr:`&optional`
                                                                                                    
                                                                                                      get_nodes_state: :zeek:type:`ClusterController::Runtime::GetNodesState` :zeek:attr:`&optional`
                                                                                                    
                                                                                                      test_state: :zeek:type:`ClusterController::Runtime::TestState` :zeek:attr:`&optional`
:zeek:id:`ClusterController::role`: :zeek:type:`ClusterController::Types::Role` :zeek:attr:`&redef` 
=================================================================================================== ================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: ClusterController::Runtime::GetNodesState
   :source-code: policy/frameworks/cluster/controller/main.zeek 35 38

   :Type: :zeek:type:`record`

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every controller/agent transaction.

   Request state specific to
   :zeek:see:`ClusterController::API::get_nodes_request` and
   :zeek:see:`ClusterController::API::get_nodes_response`.

.. zeek:type:: ClusterController::Runtime::SetConfigurationState
   :source-code: policy/frameworks/cluster/controller/main.zeek 25 30

   :Type: :zeek:type:`record`

      config: :zeek:type:`ClusterController::Types::Configuration`
         The cluster configuration established with this request

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every controller/agent transaction.

   Request state specific to
   :zeek:see:`ClusterController::API::set_configuration_request` and
   :zeek:see:`ClusterController::API::set_configuration_response`.

.. zeek:type:: ClusterController::Runtime::TestState
   :source-code: policy/frameworks/cluster/controller/main.zeek 41 42

   :Type: :zeek:type:`record`

   Dummy state for internal state-keeping test cases.


