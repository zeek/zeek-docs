:tocdepth: 3

policy/frameworks/cluster/controller/util.zeek
==============================================
.. zeek:namespace:: ClusterController::Util

Utility functions for the cluster controller framework, available to agent
and controller.

:Namespace: ClusterController::Util

Summary
~~~~~~~
Functions
#########
======================================================================== ============================================================
:zeek:id:`ClusterController::Util::set_to_vector`: :zeek:type:`function` Renders a set of strings to an alphabetically sorted vector.
======================================================================== ============================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: ClusterController::Util::set_to_vector
   :source-code: policy/frameworks/cluster/controller/util.zeek 15 26

   :Type: :zeek:type:`function` (ss: :zeek:type:`set` [:zeek:type:`string`]) : :zeek:type:`vector` of :zeek:type:`string`

   Renders a set of strings to an alphabetically sorted vector.
   

   :ss: the string set to convert.
   

   :returns: the vector of all strings in ss.


