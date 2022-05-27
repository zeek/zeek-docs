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
:Imports: :doc:`base/misc/installation.zeek </scripts/base/misc/installation.zeek>`, :doc:`policy/frameworks/management/types.zeek </scripts/policy/frameworks/management/types.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
=============================================================================== ===================================================================
:zeek:id:`Management::connect_retry`: :zeek:type:`interval` :zeek:attr:`&redef` The retry interval for Broker connnects.
:zeek:id:`Management::default_address`: :zeek:type:`string` :zeek:attr:`&redef` The fallback listen address if more specific adddresses, such as
                                                                                the controller's :zeek:see:`Management::Controller::listen_address`
                                                                                remains empty.
:zeek:id:`Management::role`: :zeek:type:`Management::Role` :zeek:attr:`&redef`  The role of this process in cluster management.
:zeek:id:`Management::spool_dir`: :zeek:type:`string` :zeek:attr:`&redef`       The toplevel directory in which the Management framework creates
                                                                                spool state for any Zeek nodes, including the Zeek cluster, agents,
                                                                                and the controller.
:zeek:id:`Management::state_dir`: :zeek:type:`string` :zeek:attr:`&redef`       The toplevel directory for variable state, such as Broker data
                                                                                stores.
=============================================================================== ===================================================================

Functions
#########
=========================================================== ===================================================================
:zeek:id:`Management::get_spool_dir`: :zeek:type:`function` Returns the effective spool directory for the management framework.
:zeek:id:`Management::get_state_dir`: :zeek:type:`function` Returns the effective state directory for the management framework.
=========================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Management::connect_retry
   :source-code: policy/frameworks/management/config.zeek 28 28

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 sec``

   The retry interval for Broker connnects. Defaults to a more
   aggressive value compared to Broker's 30s.

.. zeek:id:: Management::default_address
   :source-code: policy/frameworks/management/config.zeek 24 24

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The fallback listen address if more specific adddresses, such as
   the controller's :zeek:see:`Management::Controller::listen_address`
   remains empty. Unless redefined, this uses Broker's own default
   listen address.

.. zeek:id:: Management::role
   :source-code: policy/frameworks/management/config.zeek 18 18

   :Type: :zeek:type:`Management::Role`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Management::NONE``
   :Redefinition: from :doc:`/scripts/policy/frameworks/management/agent/main.zeek`

      ``=``::

         Management::AGENT

   :Redefinition: from :doc:`/scripts/policy/frameworks/management/controller/main.zeek`

      ``=``::

         Management::CONTROLLER

   :Redefinition: from :doc:`/scripts/policy/frameworks/management/node/main.zeek`

      ``=``::

         Management::NODE


   The role of this process in cluster management. Use this to
   differentiate code based on the type of node in which it ends up
   running.

.. zeek:id:: Management::spool_dir
   :source-code: policy/frameworks/management/config.zeek 34 34

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The toplevel directory in which the Management framework creates
   spool state for any Zeek nodes, including the Zeek cluster, agents,
   and the controller. Don't use this directly, use the
   :zeek:see:`Management::get_spool_dir` function.

.. zeek:id:: Management::state_dir
   :source-code: policy/frameworks/management/config.zeek 39 39

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   The toplevel directory for variable state, such as Broker data
   stores. Don't use this directly, use the
   :zeek:see:`Management::get_state_dir` function.

Functions
#########
.. zeek:id:: Management::get_spool_dir
   :source-code: policy/frameworks/management/config.zeek 52 58

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Returns the effective spool directory for the management framework.
   That's :zeek:see:`Management::spool_dir` when set, otherwise the
   installation's spool directory.

.. zeek:id:: Management::get_state_dir
   :source-code: policy/frameworks/management/config.zeek 60 66

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Returns the effective state directory for the management framework.
   That's :zeek:see:`Management::state_dir` when set, otherwise the
   installation's state directory.


