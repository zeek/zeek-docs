:tocdepth: 3

policy/frameworks/cluster/controller/request.zeek
=================================================
.. zeek:namespace:: ClusterController::Request


:Namespace: ClusterController::Request
:Imports: :doc:`policy/frameworks/cluster/controller/types.zeek </scripts/policy/frameworks/cluster/controller/types.zeek>`

Summary
~~~~~~~
State Variables
###############
================================================================================================= =
:zeek:id:`ClusterController::Request::null_req`: :zeek:type:`ClusterController::Request::Request` 
================================================================================================= =

Types
#####
=================================================================================== =
:zeek:type:`ClusterController::Request::Request`: :zeek:type:`record`               
:zeek:type:`ClusterController::Request::SetConfigurationState`: :zeek:type:`record` 
:zeek:type:`ClusterController::Request::SetNodesState`: :zeek:type:`record`         
:zeek:type:`ClusterController::Request::SupervisorState`: :zeek:type:`record`       
=================================================================================== =

Redefinitions
#############
===================================================================== =================================================================================================================
:zeek:type:`ClusterController::Request::Request`: :zeek:type:`record` 
                                                                      
                                                                      :New Fields: :zeek:type:`ClusterController::Request::Request`
                                                                      
                                                                        results: :zeek:type:`ClusterController::Types::ResultVec` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
                                                                      
                                                                        finished: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                                      
                                                                        set_configuration_state: :zeek:type:`ClusterController::Request::SetConfigurationState` :zeek:attr:`&optional`
                                                                      
                                                                        set_nodes_state: :zeek:type:`ClusterController::Request::SetNodesState` :zeek:attr:`&optional`
                                                                      
                                                                        supervisor_state: :zeek:type:`ClusterController::Request::SupervisorState` :zeek:attr:`&optional`
===================================================================== =================================================================================================================

Functions
#########
===================================================================== =
:zeek:id:`ClusterController::Request::create`: :zeek:type:`function`  
:zeek:id:`ClusterController::Request::finish`: :zeek:type:`function`  
:zeek:id:`ClusterController::Request::is_null`: :zeek:type:`function` 
:zeek:id:`ClusterController::Request::lookup`: :zeek:type:`function`  
===================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: ClusterController::Request::null_req
   :source-code: policy/frameworks/cluster/controller/request.zeek 40 40

   :Type: :zeek:type:`ClusterController::Request::Request`
   :Default:

      ::

         {
            id=""
            parent_id=<uninitialized>
            results=[]
            finished=T
            set_configuration_state=<uninitialized>
            set_nodes_state=<uninitialized>
            supervisor_state=<uninitialized>
         }



Types
#####
.. zeek:type:: ClusterController::Request::Request
   :source-code: policy/frameworks/cluster/controller/request.zeek 6 9

   :Type: :zeek:type:`record`

      id: :zeek:type:`string`

      parent_id: :zeek:type:`string` :zeek:attr:`&optional`

      results: :zeek:type:`ClusterController::Types::ResultVec` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`

      finished: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      set_configuration_state: :zeek:type:`ClusterController::Request::SetConfigurationState` :zeek:attr:`&optional`

      set_nodes_state: :zeek:type:`ClusterController::Request::SetNodesState` :zeek:attr:`&optional`

      supervisor_state: :zeek:type:`ClusterController::Request::SupervisorState` :zeek:attr:`&optional`


.. zeek:type:: ClusterController::Request::SetConfigurationState
   :source-code: policy/frameworks/cluster/controller/request.zeek 15 17

   :Type: :zeek:type:`record`

      requests: :zeek:type:`vector` of :zeek:type:`ClusterController::Request::Request` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`


.. zeek:type:: ClusterController::Request::SetNodesState
   :source-code: policy/frameworks/cluster/controller/request.zeek 20 22

   :Type: :zeek:type:`record`

      requests: :zeek:type:`vector` of :zeek:type:`ClusterController::Request::Request` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`


.. zeek:type:: ClusterController::Request::SupervisorState
   :source-code: policy/frameworks/cluster/controller/request.zeek 25 27

   :Type: :zeek:type:`record`

      node: :zeek:type:`string`


Functions
#########
.. zeek:id:: ClusterController::Request::create
   :source-code: policy/frameworks/cluster/controller/request.zeek 52 57

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string` :zeek:attr:`&default` = ``fD0qxAnfwOe`` :zeek:attr:`&optional`) : :zeek:type:`ClusterController::Request::Request`


.. zeek:id:: ClusterController::Request::finish
   :source-code: policy/frameworks/cluster/controller/request.zeek 67 78

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: ClusterController::Request::is_null
   :source-code: policy/frameworks/cluster/controller/request.zeek 80 86

   :Type: :zeek:type:`function` (request: :zeek:type:`ClusterController::Request::Request`) : :zeek:type:`bool`


.. zeek:id:: ClusterController::Request::lookup
   :source-code: policy/frameworks/cluster/controller/request.zeek 59 65

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string`) : :zeek:type:`ClusterController::Request::Request`



