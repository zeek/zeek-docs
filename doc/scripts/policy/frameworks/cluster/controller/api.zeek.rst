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
:zeek:id:`ClusterController::API::set_configuration_request`: :zeek:type:`event`  
:zeek:id:`ClusterController::API::set_configuration_response`: :zeek:type:`event` 
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
   :source-code: policy/frameworks/cluster/controller/main.zeek 197 209

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`)


.. zeek:id:: ClusterController::API::get_instances_response
   :source-code: policy/frameworks/cluster/controller/api.zeek 9 9

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, instances: :zeek:type:`vector` of :zeek:type:`ClusterController::Types::Instance`)


.. zeek:id:: ClusterController::API::set_configuration_request
   :source-code: policy/frameworks/cluster/controller/main.zeek 140 196

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, config: :zeek:type:`ClusterController::Types::Configuration`)


.. zeek:id:: ClusterController::API::set_configuration_response
   :source-code: policy/frameworks/cluster/controller/api.zeek 14 14

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::ResultVec`)



