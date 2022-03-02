:tocdepth: 3

policy/frameworks/management/controller/main.zeek
=================================================
.. zeek:namespace:: Management::Controller::Runtime

This is the main "runtime" of the Management framework's controller. Zeek
does not load this directly; rather, the controller's bootstrapping module
(in ./boot.zeek) specifies it as the script to run in the node newly created
by the supervisor.

:Namespace: Management::Controller::Runtime
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`policy/frameworks/management </scripts/policy/frameworks/management/index>`, :doc:`policy/frameworks/management/agent/api.zeek </scripts/policy/frameworks/management/agent/api.zeek>`, :doc:`policy/frameworks/management/agent/config.zeek </scripts/policy/frameworks/management/agent/config.zeek>`, :doc:`policy/frameworks/management/controller/api.zeek </scripts/policy/frameworks/management/controller/api.zeek>`, :doc:`policy/frameworks/management/controller/config.zeek </scripts/policy/frameworks/management/controller/config.zeek>`

Summary
~~~~~~~
Types
#####
======================================================================================== ======================================================================
:zeek:type:`Management::Controller::Runtime::GetNodesState`: :zeek:type:`record`         Request state specific to
                                                                                         :zeek:see:`Management::Controller::API::get_nodes_request` and
                                                                                         :zeek:see:`Management::Controller::API::get_nodes_response`.
:zeek:type:`Management::Controller::Runtime::SetConfigurationState`: :zeek:type:`record` Request state specific to
                                                                                         :zeek:see:`Management::Controller::API::set_configuration_request` and
                                                                                         :zeek:see:`Management::Controller::API::set_configuration_response`.
:zeek:type:`Management::Controller::Runtime::TestState`: :zeek:type:`record`             Dummy state for internal state-keeping test cases.
======================================================================================== ======================================================================

Redefinitions
#############
=================================================================================== =====================================================================================================================
:zeek:id:`Management::Log::role`: :zeek:type:`Management::Role` :zeek:attr:`&redef` 
:zeek:type:`Management::Request::Request`: :zeek:type:`record`                      
                                                                                    
                                                                                    :New Fields: :zeek:type:`Management::Request::Request`
                                                                                    
                                                                                      set_configuration_state: :zeek:type:`Management::Controller::Runtime::SetConfigurationState` :zeek:attr:`&optional`
                                                                                    
                                                                                      get_nodes_state: :zeek:type:`Management::Controller::Runtime::GetNodesState` :zeek:attr:`&optional`
                                                                                    
                                                                                      test_state: :zeek:type:`Management::Controller::Runtime::TestState` :zeek:attr:`&optional`
=================================================================================== =====================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Management::Controller::Runtime::GetNodesState
   :source-code: policy/frameworks/management/controller/main.zeek 34 37

   :Type: :zeek:type:`record`

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every controller/agent transaction.

   Request state specific to
   :zeek:see:`Management::Controller::API::get_nodes_request` and
   :zeek:see:`Management::Controller::API::get_nodes_response`.

.. zeek:type:: Management::Controller::Runtime::SetConfigurationState
   :source-code: policy/frameworks/management/controller/main.zeek 24 29

   :Type: :zeek:type:`record`

      config: :zeek:type:`Management::Configuration`
         The cluster configuration established with this request

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every controller/agent transaction.

   Request state specific to
   :zeek:see:`Management::Controller::API::set_configuration_request` and
   :zeek:see:`Management::Controller::API::set_configuration_response`.

.. zeek:type:: Management::Controller::Runtime::TestState
   :source-code: policy/frameworks/management/controller/main.zeek 40 41

   :Type: :zeek:type:`record`

   Dummy state for internal state-keeping test cases.


