:tocdepth: 3

policy/frameworks/cluster/agent/boot.zeek
=========================================

The cluster agent boot logic runs in Zeek's supervisor and instructs it to
launch an agent process. The agent's main logic resides in main.zeek,
similarly to other frameworks. The new process will execute that script.

If the current process is not the Zeek supervisor, this does nothing.

:Imports: :doc:`policy/frameworks/cluster/agent/config.zeek </scripts/policy/frameworks/cluster/agent/config.zeek>`

Summary
~~~~~~~
Redefinitions
#############
================================================================================== =
:zeek:id:`SupervisorControl::enable_listen`: :zeek:type:`bool` :zeek:attr:`&redef` 
================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

