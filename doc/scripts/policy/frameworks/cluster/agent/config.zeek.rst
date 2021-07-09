:tocdepth: 3

policy/frameworks/cluster/agent/config.zeek
===========================================
.. zeek:namespace:: ClusterAgent


:Namespace: ClusterAgent
:Imports: :doc:`policy/frameworks/cluster/controller/types.zeek </scripts/policy/frameworks/cluster/controller/types.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
========================================================================================= =
:zeek:id:`ClusterAgent::cluster_directory`: :zeek:type:`string` :zeek:attr:`&redef`       
:zeek:id:`ClusterAgent::controller`: :zeek:type:`Broker::NetworkInfo` :zeek:attr:`&redef` 
:zeek:id:`ClusterAgent::default_address`: :zeek:type:`string` :zeek:attr:`&redef`         
:zeek:id:`ClusterAgent::default_port`: :zeek:type:`port` :zeek:attr:`&redef`              
:zeek:id:`ClusterAgent::directory`: :zeek:type:`string` :zeek:attr:`&redef`               
:zeek:id:`ClusterAgent::listen_address`: :zeek:type:`string` :zeek:attr:`&redef`          
:zeek:id:`ClusterAgent::listen_port`: :zeek:type:`string` :zeek:attr:`&redef`             
:zeek:id:`ClusterAgent::name`: :zeek:type:`string` :zeek:attr:`&redef`                    
:zeek:id:`ClusterAgent::stderr_file_suffix`: :zeek:type:`string` :zeek:attr:`&redef`      
:zeek:id:`ClusterAgent::stdout_file_suffix`: :zeek:type:`string` :zeek:attr:`&redef`      
:zeek:id:`ClusterAgent::topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`            
========================================================================================= =

Functions
#########
============================================================= =
:zeek:id:`ClusterAgent::endpoint_info`: :zeek:type:`function` 
:zeek:id:`ClusterAgent::instance`: :zeek:type:`function`      
============================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: ClusterAgent::cluster_directory
   :source-code: policy/frameworks/cluster/agent/config.zeek 44 44

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``


.. zeek:id:: ClusterAgent::controller
   :source-code: policy/frameworks/cluster/agent/config.zeek 32 32

   :Type: :zeek:type:`Broker::NetworkInfo`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            address="0.0.0.0"
            bound_port=0/unknown
         }



.. zeek:id:: ClusterAgent::default_address
   :source-code: policy/frameworks/cluster/agent/config.zeek 20 20

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``


.. zeek:id:: ClusterAgent::default_port
   :source-code: policy/frameworks/cluster/agent/config.zeek 23 23

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2151/tcp``


.. zeek:id:: ClusterAgent::directory
   :source-code: policy/frameworks/cluster/agent/config.zeek 39 39

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``


.. zeek:id:: ClusterAgent::listen_address
   :source-code: policy/frameworks/cluster/agent/config.zeek 19 19

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``


.. zeek:id:: ClusterAgent::listen_port
   :source-code: policy/frameworks/cluster/agent/config.zeek 22 22

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``


.. zeek:id:: ClusterAgent::name
   :source-code: policy/frameworks/cluster/agent/config.zeek 9 9

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``


.. zeek:id:: ClusterAgent::stderr_file_suffix
   :source-code: policy/frameworks/cluster/agent/config.zeek 15 15

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"agent.stderr"``


.. zeek:id:: ClusterAgent::stdout_file_suffix
   :source-code: policy/frameworks/cluster/agent/config.zeek 14 14

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"agent.stdout"``


.. zeek:id:: ClusterAgent::topic_prefix
   :source-code: policy/frameworks/cluster/agent/config.zeek 27 27

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster-control/agent"``


Functions
#########
.. zeek:id:: ClusterAgent::endpoint_info
   :source-code: policy/frameworks/cluster/agent/config.zeek 60 86

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::EndpointInfo`


.. zeek:id:: ClusterAgent::instance
   :source-code: policy/frameworks/cluster/agent/config.zeek 52 58

   :Type: :zeek:type:`function` () : :zeek:type:`ClusterController::Types::Instance`



