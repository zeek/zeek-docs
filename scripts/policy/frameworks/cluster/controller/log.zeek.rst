:tocdepth: 3

policy/frameworks/cluster/controller/log.zeek
=============================================
.. zeek:namespace:: ClusterController::Log


:Namespace: ClusterController::Log
:Imports: :doc:`policy/frameworks/cluster/controller/config.zeek </scripts/policy/frameworks/cluster/controller/config.zeek>`

Summary
~~~~~~~
Types
#####
================================================================================ ====================================================================
:zeek:type:`ClusterController::Log::Info`: :zeek:type:`record` :zeek:attr:`&log` The record type which contains the column fields of the cluster log.
:zeek:type:`ClusterController::Log::Level`: :zeek:type:`enum`                    
================================================================================ ====================================================================

Redefinitions
#############
======================================= ==========================================
:zeek:type:`Log::ID`: :zeek:type:`enum` The cluster logging stream identifier.
                                        
                                        * :zeek:enum:`ClusterController::Log::LOG`
======================================= ==========================================

Hooks
#####
=========================================================================== =============================================
:zeek:id:`ClusterController::Log::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
=========================================================================== =============================================

Functions
#########
================================================================= =
:zeek:id:`ClusterController::Log::error`: :zeek:type:`function`   
:zeek:id:`ClusterController::Log::info`: :zeek:type:`function`    
:zeek:id:`ClusterController::Log::warning`: :zeek:type:`function` 
================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: ClusterController::Log::Info
   :source-code: policy/frameworks/cluster/controller/log.zeek 20 31

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The time at which a cluster message was generated.

      node: :zeek:type:`string` :zeek:attr:`&log`
         The name of the node that is creating the log record.

      level: :zeek:type:`string` :zeek:attr:`&log`
         Log level of this message, converted from the above Level enum

      role: :zeek:type:`string` :zeek:attr:`&log`
         The role of the node, translated from ClusterController::Types::Role.

      message: :zeek:type:`string` :zeek:attr:`&log`
         A message indicating information about cluster controller operation.
   :Attributes: :zeek:attr:`&log`

   The record type which contains the column fields of the cluster log.

.. zeek:type:: ClusterController::Log::Level
   :source-code: policy/frameworks/cluster/controller/log.zeek 12 18

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ClusterController::Log::DEBUG ClusterController::Log::Level

      .. zeek:enum:: ClusterController::Log::INFO ClusterController::Log::Level

      .. zeek:enum:: ClusterController::Log::WARNING ClusterController::Log::Level

      .. zeek:enum:: ClusterController::Log::ERROR ClusterController::Log::Level


Hooks
#####
.. zeek:id:: ClusterController::Log::log_policy
   :source-code: policy/frameworks/cluster/controller/log.zeek 10 10

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

Functions
#########
.. zeek:id:: ClusterController::Log::error
   :source-code: policy/frameworks/cluster/controller/log.zeek 85 93

   :Type: :zeek:type:`function` (message: :zeek:type:`string`) : :zeek:type:`void`


.. zeek:id:: ClusterController::Log::info
   :source-code: policy/frameworks/cluster/controller/log.zeek 65 73

   :Type: :zeek:type:`function` (message: :zeek:type:`string`) : :zeek:type:`void`


.. zeek:id:: ClusterController::Log::warning
   :source-code: policy/frameworks/cluster/controller/log.zeek 75 83

   :Type: :zeek:type:`function` (message: :zeek:type:`string`) : :zeek:type:`void`



