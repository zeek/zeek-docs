:tocdepth: 3

policy/frameworks/management/agent/config.zeek
==============================================
.. zeek:namespace:: Management::Agent

Configuration settings for a cluster agent.

:Namespace: Management::Agent
:Imports: :doc:`policy/frameworks/management </scripts/policy/frameworks/management/index>`, :doc:`policy/frameworks/management/controller/config.zeek </scripts/policy/frameworks/management/controller/config.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================================================== =====================================================================================
:zeek:id:`Management::Agent::controller`: :zeek:type:`Broker::NetworkInfo` :zeek:attr:`&redef` The network coordinates of the controller.
:zeek:id:`Management::Agent::default_port`: :zeek:type:`port` :zeek:attr:`&redef`              The fallback listen port if :zeek:see:`Management::Agent::listen_port` remains empty.
:zeek:id:`Management::Agent::directory`: :zeek:type:`string` :zeek:attr:`&redef`               An optional working directory for the agent.
:zeek:id:`Management::Agent::listen_address`: :zeek:type:`string` :zeek:attr:`&redef`          The network address the agent listens on.
:zeek:id:`Management::Agent::listen_port`: :zeek:type:`string` :zeek:attr:`&redef`             The network port the agent listens on.
:zeek:id:`Management::Agent::name`: :zeek:type:`string` :zeek:attr:`&redef`                    The name this agent uses to represent the cluster instance it
                                                                                               manages.
:zeek:id:`Management::Agent::stderr_file`: :zeek:type:`string` :zeek:attr:`&redef`             Agent stderr log configuration.
:zeek:id:`Management::Agent::stdout_file`: :zeek:type:`string` :zeek:attr:`&redef`             Agent stdout log configuration.
:zeek:id:`Management::Agent::topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`            The agent's Broker topic prefix.
============================================================================================== =====================================================================================

Functions
#########
================================================================== =====================================================================
:zeek:id:`Management::Agent::endpoint_info`: :zeek:type:`function` Returns a :zeek:see:`Broker::EndpointInfo` record for this instance.
:zeek:id:`Management::Agent::get_name`: :zeek:type:`function`      Returns the effective name of this agent.
:zeek:id:`Management::Agent::instance`: :zeek:type:`function`      Returns a :zeek:see:`Management::Instance` describing this
                                                                   instance (its agent name plus listening address/port, as applicable).
================================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Management::Agent::controller
   :source-code: policy/frameworks/management/agent/config.zeek 58 58

   :Type: :zeek:type:`Broker::NetworkInfo`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            address="127.0.0.1"
            bound_port=2150/tcp
         }


   The network coordinates of the controller. By default, the agent
   connects locally to the controller at its default port. Assigning
   a :zeek:see:`Broker::NetworkInfo` record with IP address "0.0.0.0"
   means the controller should instead connect to the agent. If you'd
   like to use that mode, make sure to set
   :zeek:see:`Management::Agent::listen_address` and
   :zeek:see:`Management::Agent::listen_port` as needed.

.. zeek:id:: Management::Agent::default_port
   :source-code: policy/frameworks/management/agent/config.zeek 45 45

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2151/tcp``

   The fallback listen port if :zeek:see:`Management::Agent::listen_port` remains empty.

.. zeek:id:: Management::Agent::directory
   :source-code: policy/frameworks/management/agent/config.zeek 66 66

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   An optional working directory for the agent. Agent and controller
   currently only log locally, not via the Zeek cluster's logger
   node. This means that if multiple agents and/or controllers work from
   the same directory, output may get garbled. When not set, defaults to
   a directory named after the agent (as per its get_name() result).

.. zeek:id:: Management::Agent::listen_address
   :source-code: policy/frameworks/management/agent/config.zeek 37 37

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network address the agent listens on. This only takes effect if
   the agent isn't configured to connect to the controller (see
   :zeek:see:`Management::Agent::controller`). By default this uses the value of the
   ZEEK_AGENT_ADDR environment variable, but you may also redef to
   a specific value. When empty, the implementation falls back to
   :zeek:see:`Management::default_address`.

.. zeek:id:: Management::Agent::listen_port
   :source-code: policy/frameworks/management/agent/config.zeek 42 42

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network port the agent listens on. Counterpart to
   :zeek:see:`Management::Agent::listen_address`, defaulting to the ZEEK_AGENT_PORT
   environment variable.

.. zeek:id:: Management::Agent::name
   :source-code: policy/frameworks/management/agent/config.zeek 16 16

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The name this agent uses to represent the cluster instance it
   manages. Defaults to the value of the ZEEK_AGENT_NAME environment
   variable. When that is unset and you don't redef the value,
   the implementation defaults to "agent-<hostname>".

.. zeek:id:: Management::Agent::stderr_file
   :source-code: policy/frameworks/management/agent/config.zeek 29 29

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"stderr"``

   Agent stderr log configuration. Like :zeek:see:`Management::Agent::stdout_file`,
   but for the stderr stream.

.. zeek:id:: Management::Agent::stdout_file
   :source-code: policy/frameworks/management/agent/config.zeek 25 25

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"stdout"``

   Agent stdout log configuration. If the string is non-empty, Zeek will
   produce a free-form log (i.e., not one governed by Zeek's logging
   framework) in the agent's working directory. If left empty, no such
   log results.
   
   Note that the agent also establishes a "proper" Zeek log via the
   :zeek:see:`Management::Log` module.

.. zeek:id:: Management::Agent::topic_prefix
   :source-code: policy/frameworks/management/agent/config.zeek 49 49

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/management/agent"``

   The agent's Broker topic prefix. For its own communication, the agent
   suffixes this with "/<name>", based on :zeek:see:`Management::Agent::get_name`.

Functions
#########
.. zeek:id:: Management::Agent::endpoint_info
   :source-code: policy/frameworks/management/agent/config.zeek 97 120

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::EndpointInfo`

   Returns a :zeek:see:`Broker::EndpointInfo` record for this instance.
   Similar to :zeek:see:`Management::Agent::instance`, but with slightly different
   data format.

.. zeek:id:: Management::Agent::get_name
   :source-code: policy/frameworks/management/agent/config.zeek 81 87

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Returns the effective name of this agent.

.. zeek:id:: Management::Agent::instance
   :source-code: policy/frameworks/management/agent/config.zeek 89 95

   :Type: :zeek:type:`function` () : :zeek:type:`Management::Instance`

   Returns a :zeek:see:`Management::Instance` describing this
   instance (its agent name plus listening address/port, as applicable).


