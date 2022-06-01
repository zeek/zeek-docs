:tocdepth: 3

policy/frameworks/management/supervisor/config.zeek
===================================================
.. zeek:namespace:: Management::Supervisor

Configuration settings for the Management framework's supervisor extension.

:Namespace: Management::Supervisor

Summary
~~~~~~~
Redefinable Options
###################
=========================================================================================== =================================================================
:zeek:id:`Management::Supervisor::output_max_lines`: :zeek:type:`count` :zeek:attr:`&redef` The maximum number of stdout/stderr output lines to convey in
                                                                                            :zeek:see:`Management::Supervisor::API::notify_node_exit` events.
:zeek:id:`Management::Supervisor::topic_prefix`: :zeek:type:`string` :zeek:attr:`&redef`    The Broker topic for Management framework communication with the
                                                                                            Supervisor.
=========================================================================================== =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Management::Supervisor::output_max_lines
   :source-code: policy/frameworks/management/supervisor/config.zeek 12 12

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100``

   The maximum number of stdout/stderr output lines to convey in
   :zeek:see:`Management::Supervisor::API::notify_node_exit` events.

.. zeek:id:: Management::Supervisor::topic_prefix
   :source-code: policy/frameworks/management/supervisor/config.zeek 8 8

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/management/supervisor"``

   The Broker topic for Management framework communication with the
   Supervisor. The agent subscribes to this.


