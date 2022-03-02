:tocdepth: 3

policy/frameworks/management/config.zeek
========================================
.. zeek:namespace:: Management

Management framework configuration settings common to agent and controller.
This does not include config settings that exist in both agent and
controller but that they set differently, since setting defaults here would
be awkward or pointless (since both node types would overwrite them
anyway). For role-specific settings, see management/controller/config.zeek
and management/agent/config.zeek.

:Namespace: Management

Summary
~~~~~~~
Redefinable Options
###################
=============================================================================== ===================================================================
:zeek:id:`Management::connect_retry`: :zeek:type:`interval` :zeek:attr:`&redef` The retry interval for Broker connnects.
:zeek:id:`Management::default_address`: :zeek:type:`string` :zeek:attr:`&redef` The fallback listen address if more specific adddresses, such as
                                                                                the controller's :zeek:see:`Management::Controller::listen_address`
                                                                                remains empty.
=============================================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Management::connect_retry
   :source-code: policy/frameworks/management/config.zeek 19 19

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   The retry interval for Broker connnects. Defaults to a more
   aggressive value compared to Broker's 30s.

.. zeek:id:: Management::default_address
   :source-code: policy/frameworks/management/config.zeek 15 15

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The fallback listen address if more specific adddresses, such as
   the controller's :zeek:see:`Management::Controller::listen_address`
   remains empty. Unless redefined, this uses Broker's own default
   listen address.


