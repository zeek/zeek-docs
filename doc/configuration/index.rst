.. _ZeekControl documentation: https://github.com/zeek/zeekctl

.. _configuration:

=====================
Cluster Configuration
=====================

A *Zeek Cluster* is a set of systems jointly analyzing the traffic of
a network link in a coordinated fashion.  You can operate such a setup from
a central manager system easily using ZeekControl because it
hides much of the complexity of the multi-machine installation.

This section gives examples of how to setup common cluster configurations
using ZeekControl.  For a full reference on ZeekControl, see the
`ZeekControl documentation`_.


Preparing to Setup a Cluster
============================

In this document we refer to the user account used to set up the cluster
as the "Zeek user".  When setting up a cluster the Zeek user must be set up
on all hosts, and this user must have ssh access from the manager to all
machines in the cluster, and it must work without being prompted for a
password/passphrase (for example, using ssh public key authentication).
Also, on the worker nodes this user must have access to the target
network interface in promiscuous mode.

Additional storage must be available on all hosts under the same path,
which we will call the cluster's prefix path.  We refer to this directory
as ``<prefix>``.  If you build Zeek from source, then ``<prefix>`` is
the directory specified with the ``--prefix`` configure option,
or ``/usr/local/zeek`` by default.  The Zeek user must be able to either
create this directory or, where it already exists, must have write
permission inside this directory on all hosts.

When trying to decide how to configure the Zeek nodes, keep in mind that
there can be multiple Zeek instances running on the same host.  For example,
it's possible to run a proxy and the manager on the same host.  However, it is
recommended to run workers on a different machine than the manager because
workers can consume a lot of CPU resources.  The maximum recommended
number of workers to run on a machine should be one or two less than
the number of CPU cores available on that machine.  Using a load-balancing
method (such as PF_RING) along with CPU pinning can decrease the load on
the worker machines.  Also, in order to reduce the load on the manager
process, it is recommended to have a logger in your configuration.  If a
logger is defined in your cluster configuration, then it will receive logs
instead of the manager process.


Basic Cluster Configuration
===========================

With all prerequisites in place, perform the following steps to setup
a Zeek cluster (do this as the Zeek user on the manager host only):

- Edit the ZeekControl configuration file, ``<prefix>/etc/zeekctl.cfg``,
  and change the value of any options to be more suitable for
  your environment.  You will most likely want to change the value of
  the ``MailTo`` and ``LogRotationInterval`` options.  A complete
  reference of all ZeekControl options can be found in the
  `ZeekControl documentation`_.

- Edit the ZeekControl node configuration file, ``<prefix>/etc/node.cfg``
  to define where logger, manager, proxies, and workers are to run.  For a
  cluster configuration, you must comment-out (or remove) the standalone node
  in that file, and either uncomment or add node entries for each node
  in your cluster (logger, manager, proxy, and workers).  For example, if you
  wanted to run five Zeek nodes (two workers, one proxy, a logger, and a
  manager) on a cluster consisting of three machines, your cluster
  configuration would look like this::

    [logger]
    type=logger
    host=10.0.0.10

    [manager]
    type=manager
    host=10.0.0.10

    [proxy-1]
    type=proxy
    host=10.0.0.10

    [worker-1]
    type=worker
    host=10.0.0.11
    interface=eth0

    [worker-2]
    type=worker
    host=10.0.0.12
    interface=eth0

  For a complete reference of all options that are allowed in the ``node.cfg``
  file, see the `ZeekControl documentation`_.

- Edit the network configuration file ``<prefix>/etc/networks.cfg``.  This
  file lists all of the networks which the cluster should consider as local
  to the monitored environment.

- Install Zeek on all machines in the cluster using ZeekControl::

    > zeekctl install

- See the `ZeekControl documentation`_
  for information on setting up a cron job on the manager host that can
  monitor the cluster.


PF_RING Cluster Configuration
=============================

`PF_RING <http://www.ntop.org/products/pf_ring/>`_ allows speeding up the
packet capture process by installing a new type of socket in Linux systems.
It supports 10Gbit hardware packet filtering using standard network adapters,
and user-space DNA (Direct NIC Access) for fast packet capture/transmission.

Installing PF_RING
^^^^^^^^^^^^^^^^^^

1. Download and install PF_RING for your system following the instructions
   `here <http://www.ntop.org/get-started/download/#PF_RING>`_.  The following
   commands will install the PF_RING libraries and kernel module (replace
   the version number 5.6.2 in this example with the version that you
   downloaded)::

     cd /usr/src
     tar xvzf PF_RING-5.6.2.tar.gz
     cd PF_RING-5.6.2/userland/lib
     ./configure --prefix=/opt/pfring
     make install

     cd ../libpcap
     ./configure --prefix=/opt/pfring
     make install

     cd ../tcpdump-4.1.1
     ./configure --prefix=/opt/pfring
     make install

     cd ../../kernel
     make install

     modprobe pf_ring enable_tx_capture=0 min_num_slots=32768

   Refer to the documentation for your Linux distribution on how to load the
   pf_ring module at boot time.  You will need to install the PF_RING
   library files and kernel module on all of the workers in your cluster.

2. Download the Zeek source code.

3. Configure and install Zeek using the following commands::

     ./configure --with-pcap=/opt/pfring
     make
     make install

4. Make sure Zeek is correctly linked to the PF_RING libpcap libraries::

     ldd /usr/local/zeek/bin/zeek | grep pcap
           libpcap.so.1 => /opt/pfring/lib/libpcap.so.1 (0x00007fa6d7d24000)

5. Configure ZeekControl to use PF_RING (explained below).

6. Run "zeekctl install" on the manager.  This command will install Zeek and
   required scripts to all machines in your cluster.

Using PF_RING
^^^^^^^^^^^^^

In order to use PF_RING, you need to specify the correct configuration
options for your worker nodes in ZeekControl's node configuration file.
Edit the ``node.cfg`` file and specify ``lb_method=pf_ring`` for each of
your worker nodes.  Next, use the ``lb_procs`` node option to specify how
many Zeek processes you'd like that worker node to run, and optionally pin
those processes to certain CPU cores with the ``pin_cpus`` option (CPU
numbering starts at zero).  The correct ``pin_cpus`` setting to use is
dependent on your CPU architecture (Intel and AMD systems enumerate
processors in different ways).  Using the wrong ``pin_cpus`` setting
can cause poor performance.  Here is what a worker node entry should
look like when using PF_RING and CPU pinning::

   [worker-1]
   type=worker
   host=10.0.0.50
   interface=eth0
   lb_method=pf_ring
   lb_procs=10
   pin_cpus=2,3,4,5,6,7,8,9,10,11


Using PF_RING+DNA with symmetric RSS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You must have a PF_RING+DNA license in order to do this.  You can sniff
each packet only once.

1. Load the DNA NIC driver (i.e. ixgbe) on each worker host.

2. Run "ethtool -L dna0 combined 10" (this will establish 10 RSS queues
   on your NIC) on each worker host.  You must make sure that you set the
   number of RSS queues to the same as the number you specify for the
   lb_procs option in the node.cfg file.

3. On the manager, configure your worker(s) in node.cfg::

       [worker-1]
       type=worker
       host=10.0.0.50
       interface=dna0
       lb_method=pf_ring
       lb_procs=10


Using PF_RING+DNA with pfdnacluster_master
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You must have a PF_RING+DNA license and a libzero license in order to do
this.  You can load balance between multiple applications and sniff the
same packets multiple times with different tools.

1. Load the DNA NIC driver (i.e. ixgbe) on each worker host.

2. Run "ethtool -L dna0 1" (this will establish 1 RSS queues on your NIC)
   on each worker host.

3. Run the pfdnacluster_master command on each worker host.  For example::

       pfdnacluster_master -c 21 -i dna0 -n 10

   Make sure that your cluster ID (21 in this example) matches the interface
   name you specify in the node.cfg file.  Also make sure that the number
   of processes you're balancing across (10 in this example) matches
   the lb_procs option in the node.cfg file.

4. If you are load balancing to other processes, you can use the
   pfringfirstappinstance variable in zeekctl.cfg to set the first
   application instance that Zeek should use.  For example, if you are running
   pfdnacluster_master with "-n 10,4" you would set
   pfringfirstappinstance=4.  Unfortunately that's still a global setting
   in zeekctl.cfg at the moment but we may change that to something you can
   set in node.cfg eventually.

5. On the manager, configure your worker(s) in node.cfg::

       [worker-1]
       type=worker
       host=10.0.0.50
       interface=dnacluster:21
       lb_method=pf_ring
       lb_procs=10

