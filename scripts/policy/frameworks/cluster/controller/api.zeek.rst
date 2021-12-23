:tocdepth: 3

policy/frameworks/cluster/controller/api.zeek
=============================================
.. zeek:namespace:: ClusterController::API


:Namespace: ClusterController::API
:Imports: :doc:`policy/frameworks/cluster/controller/types.zeek </scripts/policy/frameworks/cluster/controller/types.zeek>`

Summary
~~~~~~~
Constants
#########
============================================================== =
:zeek:id:`ClusterController::API::version`: :zeek:type:`count` 
============================================================== =

Events
######
================================================================================= =
:zeek:id:`ClusterController::API::get_instances_request`: :zeek:type:`event`      
:zeek:id:`ClusterController::API::get_instances_response`: :zeek:type:`event`     
:zeek:id:`ClusterController::API::notify_agents_ready`: :zeek:type:`event`        
:zeek:id:`ClusterController::API::set_configuration_request`: :zeek:type:`event`  
:zeek:id:`ClusterController::API::set_configuration_response`: :zeek:type:`event` 
:zeek:id:`ClusterController::API::test_timeout_request`: :zeek:type:`event`       
:zeek:id:`ClusterController::API::test_timeout_response`: :zeek:type:`event`      
================================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: ClusterController::API::version
   :source-code: policy/frameworks/cluster/controller/api.zeek 6 6

   :Type: :zeek:type:`count`
   :Default: ``1``


Events
######
.. zeek:id:: ClusterController::API::get_instances_request
   :source-code: policy/frameworks/cluster/controller/main.zeek 457 472

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)


.. zeek:id:: ClusterController::API::get_instances_response
   :source-code: policy/frameworks/cluster/controller/api.zeek 13 13

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::Result`)


.. zeek:id:: ClusterController::API::notify_agents_ready
   :source-code: policy/frameworks/cluster/controller/main.zeek 172 190

   :Type: :zeek:type:`event` (instances: :zeek:type:`set` [:zeek:type:`string`])


.. zeek:id:: ClusterController::API::set_configuration_request
   :source-code: policy/frameworks/cluster/controller/main.zeek 346 456

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, config: :zeek:type:`ClusterController::Types::Configuration`)


.. zeek:id:: ClusterController::API::set_configuration_response
   :source-code: policy/frameworks/cluster/controller/api.zeek 18 18

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::ResultVec`)


.. zeek:id:: ClusterController::API::test_timeout_request
   :source-code: policy/frameworks/cluster/controller/main.zeek 507 518

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, with_state: :zeek:type:`bool`)


.. zeek:id:: ClusterController::API::test_timeout_response
   :source-code: policy/frameworks/cluster/controller/api.zeek 29 29

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::Result`)



