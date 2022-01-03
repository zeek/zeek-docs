:tocdepth: 3

policy/frameworks/cluster/controller/config.zeek
================================================
.. zeek:namespace:: ClusterController

Configuration settings for the cluster controller.

:Namespace: ClusterController
:Imports: :doc:`policy/frameworks/cluster/agent/config.zeek </scripts/policy/frameworks/cluster/agent/config.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
=================================================================================================== ============================================================================
:zeek:id:`ClusterController::connect_retry`: :zeek:type:`interval` :zeek:attr:`&redef`              The controller's connect retry interval.
:zeek:id:`ClusterController::default_address`: :zeek:type:`string` :zeek:attr:`&redef`              The fallback listen address if :zeek:see:`ClusterController::listen_address`
                                                                                                    remains empty.
:zeek:id:`ClusterController::default_port`: :zeek:type:`port` :zeek:attr:`&redef`                   The fallback listen port if :zeek:see:`ClusterController::listen_port`
                                                                                                    remains empty.
:zeek:id:`ClusterController::directory`: :zeek:type:`string` :zeek:attr:`&redef`                    An optional custom output directory for the controller's stdout and
                                                                                                    stderr logs.
:zeek:id:`ClusterController::listen_address`: :zeek:type:`string` :zeek:attr:`&redef`               The network address the controller listens on.
:zeek:id:`ClusterController::listen_port`: :zeek:type:`string` :zeek:attr:`&redef`                  The network port the controller listens on.
:zeek:id:`ClusterController::name`: :zeek:type:`string` :zeek:attr:`&redef`                         The name of this controller.
:zeek:id:`ClusterController::request_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`            The timeout for request state.
:zeek:id:`ClusterController::role`: :zeek:type:`ClusterController::Types::Role` :zeek:attr:`&redef` The role of this process in cluster management.
:zeek:id:`ClusterController::stderr_file`: :zeek:type:`string` :zeek:attr:`&redef`                  The controller's stderr log name.
:zeek:id:`ClusterController::stdout_file`: :zeek:type:`string` :zeek:attr:`&redef`                  The controller's stdout log name.
:zeek:id:`ClusterController::topic`: :zeek:type:`string` :zeek:attr:`&redef`                        The controller's Broker topic.
=================================================================================================== ============================================================================

Functions
#########
================================================================== ============================================================================
:zeek:id:`ClusterController::endpoint_info`: :zeek:type:`function` Returns a :zeek:see:`Broker::EndpointInfo` record describing the controller.
:zeek:id:`ClusterController::network_info`: :zeek:type:`function`  Returns a :zeek:see:`Broker::NetworkInfo` record describing the controller.
================================================================== ============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: ClusterController::connect_retry
   :source-code: policy/frameworks/cluster/controller/config.zeek 49 49

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   The controller's connect retry interval. Defaults to a more
   aggressive value compared to Broker's 30s.

.. zeek:id:: ClusterController::default_address
   :source-code: policy/frameworks/cluster/controller/config.zeek 36 36

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The fallback listen address if :zeek:see:`ClusterController::listen_address`
   remains empty. Unless redefined, this uses Broker's own default
   listen address.

.. zeek:id:: ClusterController::default_port
   :source-code: policy/frameworks/cluster/controller/config.zeek 45 45

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2150/tcp``

   The fallback listen port if :zeek:see:`ClusterController::listen_port`
   remains empty.

.. zeek:id:: ClusterController::directory
   :source-code: policy/frameworks/cluster/controller/config.zeek 70 70

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   An optional custom output directory for the controller's stdout and
   stderr logs. Agent and controller currently only log locally, not via
   the data cluster's logger node. (This might change in the future.)
   This means that if both write to the same log file, the output gets
   garbled.

.. zeek:id:: ClusterController::listen_address
   :source-code: policy/frameworks/cluster/controller/config.zeek 31 31

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network address the controller listens on. By default this uses
   the value of the ZEEK_CONTROLLER_ADDR environment variable, but you
   may also redef to a specific value. When empty, the implementation
   falls back to :zeek:see:`ClusterController::default_address`.

.. zeek:id:: ClusterController::listen_port
   :source-code: policy/frameworks/cluster/controller/config.zeek 41 41

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network port the controller listens on. Counterpart to
   :zeek:see:`ClusterController::listen_address`, defaulting to the
   ZEEK_CONTROLLER_PORT environment variable.

.. zeek:id:: ClusterController::name
   :source-code: policy/frameworks/cluster/controller/config.zeek 12 12

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The name of this controller. Defaults to the value of the
   ZEEK_CONTROLLER_NAME environment variable. When that is unset and the
   user doesn't redef the value, the implementation defaults to
   "controller-<hostname>".

.. zeek:id:: ClusterController::request_timeout
   :source-code: policy/frameworks/cluster/controller/config.zeek 63 63

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 secs``

   The timeout for request state. Such state (see the :zeek:see:`ClusterController::Request`
   module) ties together request and response event pairs. The timeout causes
   its cleanup in the absence of a timely response. It applies both to
   state kept for client requests, as well as state in the agents for
   requests to the supervisor.

.. zeek:id:: ClusterController::role
   :source-code: policy/frameworks/cluster/controller/config.zeek 56 56

   :Type: :zeek:type:`ClusterController::Types::Role`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``ClusterController::Types::NONE``
   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/agent/main.zeek`

      ``=``::

         ClusterController::Types::AGENT

   :Redefinition: from :doc:`/scripts/policy/frameworks/cluster/controller/main.zeek`

      ``=``::

         ClusterController::Types::CONTROLLER


   The role of this process in cluster management. Agent and controller
   both redefine this. Used during logging.

.. zeek:id:: ClusterController::stderr_file
   :source-code: policy/frameworks/cluster/controller/config.zeek 25 25

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"controller.stderr"``

   The controller's stderr log name. Like :zeek:see:`ClusterController::stdout_file`,
   but for the stderr stream.

.. zeek:id:: ClusterController::stdout_file
   :source-code: policy/frameworks/cluster/controller/config.zeek 21 21

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"controller.stdout"``

   The controller's stdout log name. If the string is non-empty, Zeek will
   produce a free-form log (i.e., not one governed by Zeek's logging
   framework) in Zeek's working directory. If left empty, no such log
   results.
   
   Note that the controller also establishes a "proper" Zeek log via the
   :zeek:see:`ClusterController::Log` module.

.. zeek:id:: ClusterController::topic
   :source-code: policy/frameworks/cluster/controller/config.zeek 52 52

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster-control/controller"``

   The controller's Broker topic. Clients send requests to this topic.

Functions
#########
.. zeek:id:: ClusterController::endpoint_info
   :source-code: policy/frameworks/cluster/controller/config.zeek 98 111

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::EndpointInfo`

   Returns a :zeek:see:`Broker::EndpointInfo` record describing the controller.

.. zeek:id:: ClusterController::network_info
   :source-code: policy/frameworks/cluster/controller/config.zeek 79 97

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::NetworkInfo`

   Returns a :zeek:see:`Broker::NetworkInfo` record describing the controller.


