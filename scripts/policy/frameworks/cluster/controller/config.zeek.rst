:tocdepth: 3

policy/frameworks/cluster/controller/config.zeek
================================================
.. zeek:namespace:: ClusterController


:Namespace: ClusterController
:Imports: :doc:`policy/frameworks/cluster/agent/config.zeek </scripts/policy/frameworks/cluster/agent/config.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
=================================================================================================== =
:zeek:id:`ClusterController::connect_retry`: :zeek:type:`interval` :zeek:attr:`&redef`              
:zeek:id:`ClusterController::default_address`: :zeek:type:`string` :zeek:attr:`&redef`              
:zeek:id:`ClusterController::default_port`: :zeek:type:`port` :zeek:attr:`&redef`                   
:zeek:id:`ClusterController::directory`: :zeek:type:`string` :zeek:attr:`&redef`                    
:zeek:id:`ClusterController::instances`: :zeek:type:`table` :zeek:attr:`&redef`                     
:zeek:id:`ClusterController::listen_address`: :zeek:type:`string` :zeek:attr:`&redef`               
:zeek:id:`ClusterController::listen_port`: :zeek:type:`string` :zeek:attr:`&redef`                  
:zeek:id:`ClusterController::name`: :zeek:type:`string` :zeek:attr:`&redef`                         
:zeek:id:`ClusterController::role`: :zeek:type:`ClusterController::Types::Role` :zeek:attr:`&redef` 
:zeek:id:`ClusterController::stderr_file`: :zeek:type:`string` :zeek:attr:`&redef`                  
:zeek:id:`ClusterController::stdout_file`: :zeek:type:`string` :zeek:attr:`&redef`                  
:zeek:id:`ClusterController::topic`: :zeek:type:`string` :zeek:attr:`&redef`                        
=================================================================================================== =

Functions
#########
================================================================== =
:zeek:id:`ClusterController::endpoint_info`: :zeek:type:`function` 
:zeek:id:`ClusterController::network_info`: :zeek:type:`function`  
================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: ClusterController::connect_retry
   :source-code: policy/frameworks/cluster/controller/config.zeek 26 26

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``


.. zeek:id:: ClusterController::default_address
   :source-code: policy/frameworks/cluster/controller/config.zeek 20 20

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``


.. zeek:id:: ClusterController::default_port
   :source-code: policy/frameworks/cluster/controller/config.zeek 23 23

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2150/tcp``


.. zeek:id:: ClusterController::directory
   :source-code: policy/frameworks/cluster/controller/config.zeek 46 46

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``


.. zeek:id:: ClusterController::instances
   :source-code: policy/frameworks/cluster/controller/config.zeek 36 36

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`ClusterController::Types::Instance`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``


.. zeek:id:: ClusterController::listen_address
   :source-code: policy/frameworks/cluster/controller/config.zeek 19 19

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``


.. zeek:id:: ClusterController::listen_port
   :source-code: policy/frameworks/cluster/controller/config.zeek 22 22

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``


.. zeek:id:: ClusterController::name
   :source-code: policy/frameworks/cluster/controller/config.zeek 9 9

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``


.. zeek:id:: ClusterController::role
   :source-code: policy/frameworks/cluster/controller/config.zeek 40 40

   :Type: :zeek:type:`ClusterController::Types::Role`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``ClusterController::Types::NONE``
   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/agent/main.zeek`

      ``=``::

         ClusterController::Types::AGENT

   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/controller/main.zeek`

      ``=``::

         ClusterController::Types::CONTROLLER



.. zeek:id:: ClusterController::stderr_file
   :source-code: policy/frameworks/cluster/controller/config.zeek 14 14

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"controller.stderr"``


.. zeek:id:: ClusterController::stdout_file
   :source-code: policy/frameworks/cluster/controller/config.zeek 13 13

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"controller.stdout"``


.. zeek:id:: ClusterController::topic
   :source-code: policy/frameworks/cluster/controller/config.zeek 29 29

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster-control/controller"``


Functions
#########
.. zeek:id:: ClusterController::endpoint_info
   :source-code: policy/frameworks/cluster/controller/config.zeek 73 86

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::EndpointInfo`


.. zeek:id:: ClusterController::network_info
   :source-code: policy/frameworks/cluster/controller/config.zeek 54 72

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::NetworkInfo`



