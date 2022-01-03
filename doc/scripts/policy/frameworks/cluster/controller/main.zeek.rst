:tocdepth: 3

policy/frameworks/cluster/controller/main.zeek
==============================================
.. zeek:namespace:: ClusterController::Runtime

This is the main "runtime" of the cluster controller. Zeek does not load
this directly; rather, the controller's bootstrapping module (in ./boot.zeek)
specifies it as the script to run in the node newly created via Zeek's
supervisor.

:Namespace: ClusterController::Runtime
:Imports: :doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`, :doc:`policy/frameworks/cluster/agent/api.zeek </scripts/policy/frameworks/cluster/agent/api.zeek>`, :doc:`policy/frameworks/cluster/agent/config.zeek </scripts/policy/frameworks/cluster/agent/config.zeek>`, :doc:`policy/frameworks/cluster/controller/api.zeek </scripts/policy/frameworks/cluster/controller/api.zeek>`, :doc:`policy/frameworks/cluster/controller/log.zeek </scripts/policy/frameworks/cluster/controller/log.zeek>`, :doc:`policy/frameworks/cluster/controller/request.zeek </scripts/policy/frameworks/cluster/controller/request.zeek>`, :doc:`policy/frameworks/cluster/controller/util.zeek </scripts/policy/frameworks/cluster/controller/util.zeek>`

Summary
~~~~~~~
Redefinitions
#############
=================================================================================================== =
:zeek:id:`ClusterController::role`: :zeek:type:`ClusterController::Types::Role` :zeek:attr:`&redef` 
=================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

