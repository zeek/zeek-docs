:tocdepth: 3

policy/frameworks/cluster/agent/api.zeek
========================================
.. zeek:namespace:: ClusterAgent::API


:Namespace: ClusterAgent::API
:Imports: :doc:`base/frameworks/supervisor/control.zeek </scripts/base/frameworks/supervisor/control.zeek>`, :doc:`policy/frameworks/cluster/controller/types.zeek </scripts/policy/frameworks/cluster/controller/types.zeek>`

Summary
~~~~~~~
Constants
#########
========================================================= =
:zeek:id:`ClusterAgent::API::version`: :zeek:type:`count` 
========================================================= =

Events
######
============================================================================ =
:zeek:id:`ClusterAgent::API::notify_agent_hello`: :zeek:type:`event`         
:zeek:id:`ClusterAgent::API::notify_change`: :zeek:type:`event`              
:zeek:id:`ClusterAgent::API::notify_error`: :zeek:type:`event`               
:zeek:id:`ClusterAgent::API::notify_log`: :zeek:type:`event`                 
:zeek:id:`ClusterAgent::API::set_configuration_request`: :zeek:type:`event`  
:zeek:id:`ClusterAgent::API::set_configuration_response`: :zeek:type:`event` 
============================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: ClusterAgent::API::version
   :source-code: policy/frameworks/cluster/agent/api.zeek 7 7

   :Type: :zeek:type:`count`
   :Default: ``1``


Events
######
.. zeek:id:: ClusterAgent::API::notify_agent_hello
   :source-code: policy/frameworks/cluster/controller/main.zeek 12 52

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, host: :zeek:type:`addr`, api_version: :zeek:type:`count`)


.. zeek:id:: ClusterAgent::API::notify_change
   :source-code: policy/frameworks/cluster/controller/main.zeek 57 58

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, n: :zeek:type:`ClusterController::Types::Node`, old: :zeek:type:`ClusterController::Types::State`, new: :zeek:type:`ClusterController::Types::State`)


.. zeek:id:: ClusterAgent::API::notify_error
   :source-code: policy/frameworks/cluster/controller/main.zeek 62 63

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, msg: :zeek:type:`string`, node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)


.. zeek:id:: ClusterAgent::API::notify_log
   :source-code: policy/frameworks/cluster/controller/main.zeek 67 68

   :Type: :zeek:type:`event` (instance: :zeek:type:`string`, msg: :zeek:type:`string`, node: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`)


.. zeek:id:: ClusterAgent::API::set_configuration_request
   :source-code: policy/frameworks/cluster/agent/main.zeek 77 159

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, config: :zeek:type:`ClusterController::Types::Configuration`)


.. zeek:id:: ClusterAgent::API::set_configuration_response
   :source-code: policy/frameworks/cluster/controller/main.zeek 72 139

   :Type: :zeek:type:`event` (reqid: :zeek:type:`string`, result: :zeek:type:`ClusterController::Types::Result`)



