:orphan:

Package: policy/frameworks/cluster/controller
=============================================


:doc:`/scripts/policy/frameworks/cluster/controller/types.zeek`

   This module holds the basic types needed for the Cluster Controller
   framework. These are used by both agent and controller, and several
   have corresponding equals in the zeek-client implementation.

:doc:`/scripts/policy/frameworks/cluster/controller/__load__.zeek`

   The entry point for the cluster controller. It runs bootstrap logic for
   launching the controller process via Zeek's Supervisor.

:doc:`/scripts/policy/frameworks/cluster/controller/boot.zeek`

   The cluster controller's boot logic runs in Zeek's supervisor and instructs
   it to launch the controller process. The controller's main logic resides in
   main.zeek, similarly to other frameworks. The new process will execute that
   script.
   
   If the current process is not the Zeek supervisor, this does nothing.

:doc:`/scripts/policy/frameworks/cluster/controller/config.zeek`

   Configuration settings for the cluster controller.

:doc:`/scripts/policy/frameworks/cluster/controller/api.zeek`

   The event API of cluster controllers. Most endpoints consist of event pairs,
   where the controller answers a zeek-client request event with a
   corresponding response event. Such event pairs share the same name prefix
   and end in "_request" and "_response", respectively.

:doc:`/scripts/policy/frameworks/cluster/controller/log.zeek`

   This module implements straightforward logging abilities for cluster
   controller and agent. It uses Zeek's logging framework, and works only for
   nodes managed by the supervisor. In this setting Zeek's logging framework
   operates locally, i.e., this logging does not involve any logger nodes.

:doc:`/scripts/policy/frameworks/cluster/controller/request.zeek`

   This module implements a request state abstraction that both cluster
   controller and agent use to tie responses to received request events and be
   able to time-out such requests.

:doc:`/scripts/policy/frameworks/cluster/controller/util.zeek`

   Utility functions for the cluster controller framework, available to agent
   and controller.

:doc:`/scripts/policy/frameworks/cluster/controller/main.zeek`

   This is the main "runtime" of the cluster controller. Zeek does not load
   this directly; rather, the controller's bootstrapping module (in ./boot.zeek)
   specifies it as the script to run in the node newly created via Zeek's
   supervisor.

