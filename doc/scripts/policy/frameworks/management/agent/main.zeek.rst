:tocdepth: 3

policy/frameworks/management/agent/main.zeek
============================================
.. zeek:namespace:: Mangement::Agent::Runtime

This is the main "runtime" of a cluster agent. Zeek does not load this
directly; rather, the agent's bootstrapping module (in ./boot.zeek)
specifies it as the script to run in the node newly created via Zeek's
supervisor.

:Namespace: Mangement::Agent::Runtime
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`policy/frameworks/management </scripts/policy/frameworks/management/index>`, :doc:`policy/frameworks/management/agent/api.zeek </scripts/policy/frameworks/management/agent/api.zeek>`, :doc:`policy/frameworks/management/agent/config.zeek </scripts/policy/frameworks/management/agent/config.zeek>`, :doc:`policy/frameworks/management/node/api.zeek </scripts/policy/frameworks/management/node/api.zeek>`, :doc:`policy/frameworks/management/node/config.zeek </scripts/policy/frameworks/management/node/config.zeek>`

Summary
~~~~~~~
Types
#####
============================================================================== ================================================================
:zeek:type:`Mangement::Agent::Runtime::NodeDispatchState`: :zeek:type:`record` Request state for node dispatches, tracking the requested action
                                                                               as well as received responses.
:zeek:type:`Mangement::Agent::Runtime::SupervisorState`: :zeek:type:`record`   Request state specific to the agent's Supervisor interactions.
============================================================================== ================================================================

Redefinitions
#############
=================================================================================== ==================================================================================================
:zeek:id:`Management::Log::role`: :zeek:type:`Management::Role` :zeek:attr:`&redef` 
:zeek:type:`Management::Request::Request`: :zeek:type:`record`                      
                                                                                    
                                                                                    :New Fields: :zeek:type:`Management::Request::Request`
                                                                                    
                                                                                      supervisor_state: :zeek:type:`Mangement::Agent::Runtime::SupervisorState` :zeek:attr:`&optional`
=================================================================================== ==================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Mangement::Agent::Runtime::NodeDispatchState
   :source-code: policy/frameworks/management/agent/main.zeek 27 34

   :Type: :zeek:type:`record`

      action: :zeek:type:`vector` of :zeek:type:`string`
         The dispatched action. The first string is a command,
         any remaining strings its arguments.

      requests: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
         Request state for every node managed by this agent.

   Request state for node dispatches, tracking the requested action
   as well as received responses.

.. zeek:type:: Mangement::Agent::Runtime::SupervisorState
   :source-code: policy/frameworks/management/agent/main.zeek 21 23

   :Type: :zeek:type:`record`

      node: :zeek:type:`string`
         Name of the node the Supervisor is acting on.

   Request state specific to the agent's Supervisor interactions.


