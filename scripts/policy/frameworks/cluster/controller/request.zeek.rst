:tocdepth: 3

policy/frameworks/cluster/controller/request.zeek
=================================================
.. zeek:namespace:: ClusterController::Request


:Namespace: ClusterController::Request
:Imports: :doc:`policy/frameworks/cluster/controller/config.zeek </scripts/policy/frameworks/cluster/controller/config.zeek>`, :doc:`policy/frameworks/cluster/controller/types.zeek </scripts/policy/frameworks/cluster/controller/types.zeek>`

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
:zeek:type:`ClusterController::Request::SupervisorState`: :zeek:type:`record`       
:zeek:type:`ClusterController::Request::TestState`: :zeek:type:`record`             
=================================================================================== =

Redefinitions
#############
===================================================================== =================================================================================================================
:zeek:type:`ClusterController::Request::Request`: :zeek:type:`record` 
                                                                      
                                                                      :New Fields: :zeek:type:`ClusterController::Request::Request`
                                                                      
                                                                        results: :zeek:type:`ClusterController::Types::ResultVec` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
                                                                      
                                                                        finished: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                                      
                                                                        set_configuration_state: :zeek:type:`ClusterController::Request::SetConfigurationState` :zeek:attr:`&optional`
                                                                      
                                                                        supervisor_state: :zeek:type:`ClusterController::Request::SupervisorState` :zeek:attr:`&optional`
                                                                      
                                                                        test_state: :zeek:type:`ClusterController::Request::TestState` :zeek:attr:`&optional`
===================================================================== =================================================================================================================

Events
######
========================================================================== =
:zeek:id:`ClusterController::Request::request_expired`: :zeek:type:`event` 
========================================================================== =

Functions
#########
======================================================================= =
:zeek:id:`ClusterController::Request::create`: :zeek:type:`function`    
:zeek:id:`ClusterController::Request::finish`: :zeek:type:`function`    
:zeek:id:`ClusterController::Request::is_null`: :zeek:type:`function`   
:zeek:id:`ClusterController::Request::lookup`: :zeek:type:`function`    
:zeek:id:`ClusterController::Request::to_string`: :zeek:type:`function` 
======================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: ClusterController::Request::null_req
   :source-code: policy/frameworks/cluster/controller/request.zeek 43 43

   :Type: :zeek:type:`ClusterController::Request::Request`
   :Default:

      ::

         {
            id=""
            parent_id=<uninitialized>
            results=[]
            finished=T
            set_configuration_state=<uninitialized>
            supervisor_state=<uninitialized>
            test_state=<uninitialized>
         }



Types
#####
.. zeek:type:: ClusterController::Request::Request
   :source-code: policy/frameworks/cluster/controller/request.zeek 7 10

   :Type: :zeek:type:`record`

      id: :zeek:type:`string`

      parent_id: :zeek:type:`string` :zeek:attr:`&optional`

      results: :zeek:type:`ClusterController::Types::ResultVec` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`

      finished: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      set_configuration_state: :zeek:type:`ClusterController::Request::SetConfigurationState` :zeek:attr:`&optional`

      supervisor_state: :zeek:type:`ClusterController::Request::SupervisorState` :zeek:attr:`&optional`

      test_state: :zeek:type:`ClusterController::Request::TestState` :zeek:attr:`&optional`


.. zeek:type:: ClusterController::Request::SetConfigurationState
   :source-code: policy/frameworks/cluster/controller/request.zeek 18 21

   :Type: :zeek:type:`record`

      config: :zeek:type:`ClusterController::Types::Configuration`

      requests: :zeek:type:`vector` of :zeek:type:`ClusterController::Request::Request` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`


.. zeek:type:: ClusterController::Request::SupervisorState
   :source-code: policy/frameworks/cluster/controller/request.zeek 24 26

   :Type: :zeek:type:`record`

      node: :zeek:type:`string`


.. zeek:type:: ClusterController::Request::TestState
   :source-code: policy/frameworks/cluster/controller/request.zeek 29 30

   :Type: :zeek:type:`record`


Events
######
.. zeek:id:: ClusterController::Request::request_expired
   :source-code: policy/frameworks/cluster/controller/main.zeek 473 506

   :Type: :zeek:type:`event` (req: :zeek:type:`ClusterController::Request::Request`)


Functions
#########
.. zeek:id:: ClusterController::Request::create
   :source-code: policy/frameworks/cluster/controller/request.zeek 69 74

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string` :zeek:attr:`&default` = ``9Ye7pQPhuMe`` :zeek:attr:`&optional`) : :zeek:type:`ClusterController::Request::Request`


.. zeek:id:: ClusterController::Request::finish
   :source-code: policy/frameworks/cluster/controller/request.zeek 84 95

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string`) : :zeek:type:`bool`


.. zeek:id:: ClusterController::Request::is_null
   :source-code: policy/frameworks/cluster/controller/request.zeek 97 103

   :Type: :zeek:type:`function` (request: :zeek:type:`ClusterController::Request::Request`) : :zeek:type:`bool`


.. zeek:id:: ClusterController::Request::lookup
   :source-code: policy/frameworks/cluster/controller/request.zeek 76 82

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string`) : :zeek:type:`ClusterController::Request::Request`


.. zeek:id:: ClusterController::Request::to_string
   :source-code: policy/frameworks/cluster/controller/request.zeek 105 124

   :Type: :zeek:type:`function` (request: :zeek:type:`ClusterController::Request::Request`) : :zeek:type:`string`



