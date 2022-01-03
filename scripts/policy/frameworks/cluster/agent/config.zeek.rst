:tocdepth: 3

policy/frameworks/cluster/agent/config.zeek
===========================================
.. zeek:namespace:: ClusterAgent

Configuration settings for a cluster agent.

:Namespace: ClusterAgent
:Imports: :doc:`policy/frameworks/cluster/controller/types.zeek </scripts/policy/frameworks/cluster/controller/types.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
========================================================================================= ================================================================================
:zeek:id:`ClusterAgent::cluster_directory`: :zeek:type:`string` :zeek:attr:`&redef`       The working directory for data cluster nodes created by this
                                                                                          agent.
:zeek:id:`ClusterAgent::controller`: :zeek:type:`Broker::NetworkInfo` :zeek:attr:`&redef` The network coordinates of the controller.
:zeek:id:`ClusterAgent::default_address`: :zeek:type:`string` :zeek:attr:`&redef`         The fallback listen address if :zeek:see:`ClusterAgent::listen_address`
                                                                                          remains empty.
:zeek:id:`ClusterAgent::default_port`: :zeek:type:`port` :zeek:attr:`&redef`              The fallback listen port if :zeek:see:`ClusterAgent::listen_port` remains empty.
:zeek:id:`ClusterAgent::directory`: :zeek:type:`string` :zeek:attr:`&redef`               An optional custom output directory for the agent's stdout and stderr
                                                                                          logs.
:zeek:id:`ClusterAgent::listen_address`: :zeek:type:`string` :zeek:attr:`&redef`          The network address the agent listens on.
:zeek:id:`ClusterAgent::listen_port`: :zeek:type:`string` :zeek:attr:`&redef`             The network port the agent listens on.
:zeek:id:`ClusterAgent::name`: :zeek:type:`string` :zeek:attr:`&redef`                    The name this agent uses to represent the cluster instance it
                                                                                          manages.
:zeek:id:`ClusterAgent::stderr_file_suffix`: :zeek:type:`string` :zeek:attr:`&redef`      Agent stderr log configuration.
:zeek:id:`ClusterAgent::stdout_file_suffix`: :zeek:type:`string` :zeek:attr:`&redef`      Agent stdout log configuration.
:zeek:id:`ClusterAgent::topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`            The agent's Broker topic prefix.
========================================================================================= ================================================================================

Functions
#########
============================================================= ========================================================================
:zeek:id:`ClusterAgent::endpoint_info`: :zeek:type:`function` Returns a :zeek:see:`Broker::EndpointInfo` record for this instance.
:zeek:id:`ClusterAgent::instance`: :zeek:type:`function`      Returns a :zeek:see:`ClusterController::Types::Instance` describing this
                                                              instance (its agent name plus listening address/port, as applicable).
============================================================= ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: ClusterAgent::cluster_directory
   :source-code: policy/frameworks/cluster/agent/config.zeek 72 72

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The working directory for data cluster nodes created by this
   agent. If you make this a relative path, note that the path is
   relative to the agent's working directory, since it creates data
   cluster nodes.

.. zeek:id:: ClusterAgent::controller
   :source-code: policy/frameworks/cluster/agent/config.zeek 58 58

   :Type: :zeek:type:`Broker::NetworkInfo`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            address="0.0.0.0"
            bound_port=0/unknown
         }


   The network coordinates of the controller. When defined, the agent
   peers with (and connects to) the controller; otherwise the controller
   will peer (and connect to) the agent, listening as defined by
   :zeek:see:`ClusterAgent::listen_address` and :zeek:see:`ClusterAgent::listen_port`.

.. zeek:id:: ClusterAgent::default_address
   :source-code: policy/frameworks/cluster/agent/config.zeek 40 40

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The fallback listen address if :zeek:see:`ClusterAgent::listen_address`
   remains empty. Unless redefined, this uses Broker's own default listen
   address.

.. zeek:id:: ClusterAgent::default_port
   :source-code: policy/frameworks/cluster/agent/config.zeek 48 48

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2151/tcp``

   The fallback listen port if :zeek:see:`ClusterAgent::listen_port` remains empty.

.. zeek:id:: ClusterAgent::directory
   :source-code: policy/frameworks/cluster/agent/config.zeek 66 66

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   An optional custom output directory for the agent's stdout and stderr
   logs. Agent and controller currently only log locally, not via the
   data cluster's logger node. (This might change in the future.) This
   means that if both write to the same log file, the output gets
   garbled.

.. zeek:id:: ClusterAgent::listen_address
   :source-code: policy/frameworks/cluster/agent/config.zeek 35 35

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network address the agent listens on. This only takes effect if
   the agent isn't configured to connect to the controller (see
   :zeek:see:`ClusterAgent::controller`). By default this uses the value of the
   ZEEK_AGENT_ADDR environment variable, but you may also redef to
   a specific value. When empty, the implementation falls back to
   :zeek:see:`ClusterAgent::default_address`.

.. zeek:id:: ClusterAgent::listen_port
   :source-code: policy/frameworks/cluster/agent/config.zeek 45 45

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network port the agent listens on. Counterpart to
   :zeek:see:`ClusterAgent::listen_address`, defaulting to the ZEEK_AGENT_PORT
   environment variable.

.. zeek:id:: ClusterAgent::name
   :source-code: policy/frameworks/cluster/agent/config.zeek 12 12

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The name this agent uses to represent the cluster instance it
   manages. Defaults to the value of the ZEEK_AGENT_NAME environment
   variable. When that is unset and you don't redef the value,
   the implementation defaults to "agent-<hostname>".

.. zeek:id:: ClusterAgent::stderr_file_suffix
   :source-code: policy/frameworks/cluster/agent/config.zeek 27 27

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"agent.stderr"``

   Agent stderr log configuration. Like :zeek:see:`ClusterAgent::stdout_file_suffix`,
   but for the stderr stream.

.. zeek:id:: ClusterAgent::stdout_file_suffix
   :source-code: policy/frameworks/cluster/agent/config.zeek 23 23

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"agent.stdout"``

   Agent stdout log configuration. If the string is non-empty, Zeek will
   produce a free-form log (i.e., not one governed by Zeek's logging
   framework) in Zeek's working directory. The final log's name is
   "<name>.<suffix>", where the name is taken from :zeek:see:`ClusterAgent::name`,
   and the suffix is defined by the following variable. If left empty,
   no such log results.
   
   Note that the agent also establishes a "proper" Zeek log via the
   :zeek:see:`ClusterController::Log` module.

.. zeek:id:: ClusterAgent::topic_prefix
   :source-code: policy/frameworks/cluster/agent/config.zeek 52 52

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/cluster-control/agent"``

   The agent's Broker topic prefix. For its own communication, the agent
   suffixes this with "/<name>", based on :zeek:see:`ClusterAgent::name`.

Functions
#########
.. zeek:id:: ClusterAgent::endpoint_info
   :source-code: policy/frameworks/cluster/agent/config.zeek 92 118

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::EndpointInfo`

   Returns a :zeek:see:`Broker::EndpointInfo` record for this instance.
   Similar to :zeek:see:`ClusterAgent::instance`, but with slightly different
   data format.

.. zeek:id:: ClusterAgent::instance
   :source-code: policy/frameworks/cluster/agent/config.zeek 84 90

   :Type: :zeek:type:`function` () : :zeek:type:`ClusterController::Types::Instance`

   Returns a :zeek:see:`ClusterController::Types::Instance` describing this
   instance (its agent name plus listening address/port, as applicable).


