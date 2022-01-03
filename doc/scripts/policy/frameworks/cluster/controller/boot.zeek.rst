:tocdepth: 3

policy/frameworks/cluster/controller/boot.zeek
==============================================

The cluster controller's boot logic runs in Zeek's supervisor and instructs
it to launch the controller process. The controller's main logic resides in
main.zeek, similarly to other frameworks. The new process will execute that
script.

If the current process is not the Zeek supervisor, this does nothing.

:Imports: :doc:`policy/frameworks/cluster/controller/config.zeek </scripts/policy/frameworks/cluster/controller/config.zeek>`

Summary
~~~~~~~

Detailed Interface
~~~~~~~~~~~~~~~~~~

