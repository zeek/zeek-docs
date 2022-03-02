:tocdepth: 3

policy/frameworks/management/controller/config.zeek
===================================================
.. zeek:namespace:: Management::Controller

Configuration settings for the cluster controller.

:Namespace: Management::Controller
:Imports: :doc:`policy/frameworks/management/config.zeek </scripts/policy/frameworks/management/config.zeek>`, :doc:`policy/frameworks/management/types.zeek </scripts/policy/frameworks/management/types.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
========================================================================================== ===========================================================================
:zeek:id:`Management::Controller::default_port`: :zeek:type:`port` :zeek:attr:`&redef`     The fallback listen port if :zeek:see:`Management::Controller::listen_port`
                                                                                           remains empty.
:zeek:id:`Management::Controller::directory`: :zeek:type:`string` :zeek:attr:`&redef`      An optional custom output directory for stdout/stderr.
:zeek:id:`Management::Controller::listen_address`: :zeek:type:`string` :zeek:attr:`&redef` The network address the controller listens on.
:zeek:id:`Management::Controller::listen_port`: :zeek:type:`string` :zeek:attr:`&redef`    The network port the controller listens on.
:zeek:id:`Management::Controller::name`: :zeek:type:`string` :zeek:attr:`&redef`           The name of this controller.
:zeek:id:`Management::Controller::stderr_file`: :zeek:type:`string` :zeek:attr:`&redef`    The controller's stderr log name.
:zeek:id:`Management::Controller::stdout_file`: :zeek:type:`string` :zeek:attr:`&redef`    The controller's stdout log name.
:zeek:id:`Management::Controller::topic`: :zeek:type:`string` :zeek:attr:`&redef`          The controller's Broker topic.
========================================================================================== ===========================================================================

Functions
#########
======================================================================= ============================================================================
:zeek:id:`Management::Controller::endpoint_info`: :zeek:type:`function` Returns a :zeek:see:`Broker::EndpointInfo` record describing the controller.
:zeek:id:`Management::Controller::network_info`: :zeek:type:`function`  Returns a :zeek:see:`Broker::NetworkInfo` record describing the controller.
======================================================================= ============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Management::Controller::default_port
   :source-code: policy/frameworks/management/controller/config.zeek 41 41

   :Type: :zeek:type:`port`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``2150/tcp``

   The fallback listen port if :zeek:see:`Management::Controller::listen_port`
   remains empty.

.. zeek:id:: Management::Controller::directory
   :source-code: policy/frameworks/management/controller/config.zeek 50 50

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   An optional custom output directory for stdout/stderr. Agent and
   controller currently only log locally, not via the data cluster's
   logger node. This means that if both write to the same log file,
   output gets garbled.

.. zeek:id:: Management::Controller::listen_address
   :source-code: policy/frameworks/management/controller/config.zeek 32 32

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network address the controller listens on. By default this uses
   the value of the ZEEK_CONTROLLER_ADDR environment variable, but you
   may also redef to a specific value. When empty, the implementation
   falls back to :zeek:see:`Management::default_address`.

.. zeek:id:: Management::Controller::listen_port
   :source-code: policy/frameworks/management/controller/config.zeek 37 37

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The network port the controller listens on. Counterpart to
   :zeek:see:`Management::Controller::listen_address`, defaulting to the
   ZEEK_CONTROLLER_PORT environment variable.

.. zeek:id:: Management::Controller::name
   :source-code: policy/frameworks/management/controller/config.zeek 13 13

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The name of this controller. Defaults to the value of the
   ZEEK_CONTROLLER_NAME environment variable. When that is unset and the
   user doesn't redef the value, the implementation defaults to
   "controller-<hostname>".

.. zeek:id:: Management::Controller::stderr_file
   :source-code: policy/frameworks/management/controller/config.zeek 26 26

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"controller.stderr"``

   The controller's stderr log name. Like :zeek:see:`Management::Controller::stdout_file`,
   but for the stderr stream.

.. zeek:id:: Management::Controller::stdout_file
   :source-code: policy/frameworks/management/controller/config.zeek 22 22

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"controller.stdout"``

   The controller's stdout log name. If the string is non-empty, Zeek will
   produce a free-form log (i.e., not one governed by Zeek's logging
   framework) in Zeek's working directory. If left empty, no such log
   results.
   
   Note that the controller also establishes a "proper" Zeek log via the
   :zeek:see:`Management::Log` module.

.. zeek:id:: Management::Controller::topic
   :source-code: policy/frameworks/management/controller/config.zeek 44 44

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/management/controller"``

   The controller's Broker topic. Clients send requests to this topic.

Functions
#########
.. zeek:id:: Management::Controller::endpoint_info
   :source-code: policy/frameworks/management/controller/config.zeek 78 91

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::EndpointInfo`

   Returns a :zeek:see:`Broker::EndpointInfo` record describing the controller.

.. zeek:id:: Management::Controller::network_info
   :source-code: policy/frameworks/management/controller/config.zeek 59 77

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::NetworkInfo`

   Returns a :zeek:see:`Broker::NetworkInfo` record describing the controller.


