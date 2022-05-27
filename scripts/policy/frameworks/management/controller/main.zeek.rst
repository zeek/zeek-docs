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
:zeek:type:`Management::Controller::Runtime::NodeDispatchState`: :zeek:type:`record`     Request state for node dispatch requests, to track the requested
                                                                                         action and received responses.
:zeek:type:`Management::Controller::Runtime::SetConfigurationState`: :zeek:type:`record` Request state specific to
                                                                                         :zeek:see:`Management::Controller::API::set_configuration_request` and
                                                                                         :zeek:see:`Management::Controller::API::set_configuration_response`.
:zeek:type:`Management::Controller::Runtime::TestState`: :zeek:type:`record`             Dummy state for internal state-keeping test cases.
======================================================================================== ======================================================================

Redefinitions
#############
============================================================================== =====================================================================================================================
:zeek:type:`Management::Request::Request`: :zeek:type:`record`                 
                                                                               
                                                                               :New Fields: :zeek:type:`Management::Request::Request`
                                                                               
                                                                                 node_dispatch_state: :zeek:type:`Mangement::Agent::Runtime::NodeDispatchState` :zeek:attr:`&optional`
                                                                               
                                                                                 set_configuration_state: :zeek:type:`Management::Controller::Runtime::SetConfigurationState` :zeek:attr:`&optional`
                                                                               
                                                                                 get_nodes_state: :zeek:type:`Management::Controller::Runtime::GetNodesState` :zeek:attr:`&optional`
                                                                               
                                                                                 node_dispatch_state: :zeek:type:`Management::Controller::Runtime::NodeDispatchState` :zeek:attr:`&optional`
                                                                               
                                                                                 test_state: :zeek:type:`Management::Controller::Runtime::TestState` :zeek:attr:`&optional`
:zeek:id:`Management::role`: :zeek:type:`Management::Role` :zeek:attr:`&redef` 
============================================================================== =====================================================================================================================


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

.. zeek:type:: Management::Controller::Runtime::NodeDispatchState
   :source-code: policy/frameworks/management/controller/main.zeek 50 60

   :Type: :zeek:type:`record`

      action: :zeek:type:`vector` of :zeek:type:`string`
         The dispatched action. The first string is a command,
         any remaining strings its arguments.

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every controller/agent transaction.
         The set of strings tracks the node names from which
         we still expect responses, before we can respond back
         to the client.

   Request state for node dispatch requests, to track the requested
   action and received responses. Node dispatches are requests to
   execute pre-implemented actions on every node in the cluster,
   and report their outcomes. See
   :zeek:see:`Management::Agent::API::node_dispatch_request` and
   :zeek:see:`Management::Agent::API::node_dispatch_response` for the
   agent/controller interaction, and
   :zeek:see:`Management::Controller::API::get_id_value_request` and
   :zeek:see:`Management::Controller::API::get_id_value_response`
   for an example of a specific API the controller generalizes into
   a dispatch.

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
   :source-code: policy/frameworks/management/controller/main.zeek 63 64

   :Type: :zeek:type:`record`

   Dummy state for internal state-keeping test cases.


