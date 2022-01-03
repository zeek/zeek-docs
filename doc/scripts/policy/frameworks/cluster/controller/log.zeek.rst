:tocdepth: 3

policy/frameworks/cluster/controller/log.zeek
=============================================
.. zeek:namespace:: ClusterController::Log

This module implements straightforward logging abilities for cluster
controller and agent. It uses Zeek's logging framework, and works only for
nodes managed by the supervisor. In this setting Zeek's logging framework
operates locally, i.e., this logging does not involve any logger nodes.

:Namespace: ClusterController::Log
:Imports: :doc:`policy/frameworks/cluster/controller/config.zeek </scripts/policy/frameworks/cluster/controller/config.zeek>`

Summary
~~~~~~~
Types
#####
================================================================================ =========================================================================
:zeek:type:`ClusterController::Log::Info`: :zeek:type:`record` :zeek:attr:`&log` The record type containing the column fields of the agent/controller log.
:zeek:type:`ClusterController::Log::Level`: :zeek:type:`enum`                    The controller/agent log supports four different log levels.
================================================================================ =========================================================================

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
================================================================= ===================================
:zeek:id:`ClusterController::Log::debug`: :zeek:type:`function`   A debug-level log message writer.
:zeek:id:`ClusterController::Log::error`: :zeek:type:`function`   An error-level log message writer.
:zeek:id:`ClusterController::Log::info`: :zeek:type:`function`    An info-level log message writer.
:zeek:id:`ClusterController::Log::warning`: :zeek:type:`function` A warning-level log message writer.
================================================================= ===================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: ClusterController::Log::Info
   :source-code: policy/frameworks/cluster/controller/log.zeek 26 37

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

   The record type containing the column fields of the agent/controller log.

.. zeek:type:: ClusterController::Log::Level
   :source-code: policy/frameworks/cluster/controller/log.zeek 18 24

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ClusterController::Log::DEBUG ClusterController::Log::Level

      .. zeek:enum:: ClusterController::Log::INFO ClusterController::Log::Level

      .. zeek:enum:: ClusterController::Log::WARNING ClusterController::Log::Level

      .. zeek:enum:: ClusterController::Log::ERROR ClusterController::Log::Level

   The controller/agent log supports four different log levels.

Hooks
#####
.. zeek:id:: ClusterController::Log::log_policy
   :source-code: policy/frameworks/cluster/controller/log.zeek 15 15

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.

Functions
#########
.. zeek:id:: ClusterController::Log::debug
   :source-code: policy/frameworks/cluster/controller/log.zeek 83 91

   :Type: :zeek:type:`function` (message: :zeek:type:`string`) : :zeek:type:`void`

   A debug-level log message writer.
   

   :message: the message to log.
   

.. zeek:id:: ClusterController::Log::error
   :source-code: policy/frameworks/cluster/controller/log.zeek 113 121

   :Type: :zeek:type:`function` (message: :zeek:type:`string`) : :zeek:type:`void`

   An error-level log message writer. (This only logs a message, it does not
   terminate Zeek or have other runtime effects.)
   

   :message: the message to log.
   

.. zeek:id:: ClusterController::Log::info
   :source-code: policy/frameworks/cluster/controller/log.zeek 93 101

   :Type: :zeek:type:`function` (message: :zeek:type:`string`) : :zeek:type:`void`

   An info-level log message writer.
   

   :message: the message to log.
   

.. zeek:id:: ClusterController::Log::warning
   :source-code: policy/frameworks/cluster/controller/log.zeek 103 111

   :Type: :zeek:type:`function` (message: :zeek:type:`string`) : :zeek:type:`void`

   A warning-level log message writer.
   

   :message: the message to log.
   


