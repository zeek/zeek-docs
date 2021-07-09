:tocdepth: 3

policy/frameworks/cluster/agent/main.zeek
=========================================


:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`policy/frameworks/cluster/agent/api.zeek </scripts/policy/frameworks/cluster/agent/api.zeek>`, :doc:`policy/frameworks/cluster/controller/config.zeek </scripts/policy/frameworks/cluster/controller/config.zeek>`, :doc:`policy/frameworks/cluster/controller/log.zeek </scripts/policy/frameworks/cluster/controller/log.zeek>`, :doc:`policy/frameworks/cluster/controller/request.zeek </scripts/policy/frameworks/cluster/controller/request.zeek>`

Summary
~~~~~~~
State Variables
###############
============================================================================== =
:zeek:id:`data_cluster`: :zeek:type:`table`                                    
:zeek:id:`global_config`: :zeek:type:`ClusterController::Types::Configuration` 
:zeek:id:`instances`: :zeek:type:`table`                                       
:zeek:id:`nodes`: :zeek:type:`table`                                           
============================================================================== =

Redefinitions
#############
=================================================================================================== =
:zeek:id:`ClusterController::role`: :zeek:type:`ClusterController::Types::Role` :zeek:attr:`&redef` 
=================================================================================================== =

Functions
#########
==================================================== =
:zeek:id:`supervisor_create`: :zeek:type:`function`  
:zeek:id:`supervisor_destroy`: :zeek:type:`function` 
==================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: data_cluster
   :source-code: policy/frameworks/cluster/agent/main.zeek 23 23

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Supervisor::ClusterEndpoint`
   :Default: ``{}``


.. zeek:id:: global_config
   :source-code: policy/frameworks/cluster/agent/main.zeek 12 12

   :Type: :zeek:type:`ClusterController::Types::Configuration`
   :Default:

      ::

         {
            id="rFj3eGxkRR5"
            instances={

            }
            nodes={

            }
         }



.. zeek:id:: instances
   :source-code: policy/frameworks/cluster/agent/main.zeek 15 15

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`ClusterController::Types::Instance`
   :Default: ``{}``


.. zeek:id:: nodes
   :source-code: policy/frameworks/cluster/agent/main.zeek 18 18

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`ClusterController::Types::Node`
   :Default: ``{}``


Functions
#########
.. zeek:id:: supervisor_create
   :source-code: policy/frameworks/cluster/agent/main.zeek 61 67

   :Type: :zeek:type:`function` (nc: :zeek:type:`Supervisor::NodeConfig`) : :zeek:type:`void`


.. zeek:id:: supervisor_destroy
   :source-code: policy/frameworks/cluster/agent/main.zeek 69 75

   :Type: :zeek:type:`function` (node: :zeek:type:`string`) : :zeek:type:`void`



