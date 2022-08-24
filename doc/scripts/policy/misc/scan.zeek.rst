:tocdepth: 3

policy/misc/scan.zeek
=====================
.. zeek:namespace:: Scan

TCP Scan detection.

:Namespace: Scan
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`, :doc:`base/utils/time.zeek </scripts/base/utils/time.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================================== ==================================================================
:zeek:id:`Scan::addr_scan_interval`: :zeek:type:`interval` :zeek:attr:`&redef` Failed connection attempts are tracked over this time interval for
                                                                               the address scan detection.
:zeek:id:`Scan::addr_scan_threshold`: :zeek:type:`double` :zeek:attr:`&redef`  The threshold of the unique number of hosts a scanning host has to
                                                                               have failed connections with on a single port.
:zeek:id:`Scan::port_scan_interval`: :zeek:type:`interval` :zeek:attr:`&redef` Failed connection attempts are tracked over this time interval for
                                                                               the port scan detection.
:zeek:id:`Scan::port_scan_threshold`: :zeek:type:`double` :zeek:attr:`&redef`  The threshold of the number of unique ports a scanning host has to
                                                                               have failed connections with on a single victim host.
============================================================================== ==================================================================

Redefinitions
#############
============================================ ==============================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`Scan::Address_Scan`:
                                               Address scans detect that a host appears to be scanning some
                                               number of destinations on a single port.
                                             
                                             * :zeek:enum:`Scan::Port_Scan`:
                                               Port scans detect that an attacking host appears to be
                                               scanning a single victim host on several ports.
============================================ ==============================================================

Hooks
#####
==================================================== =
:zeek:id:`Scan::addr_scan_policy`: :zeek:type:`hook` 
:zeek:id:`Scan::port_scan_policy`: :zeek:type:`hook` 
==================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Scan::addr_scan_interval
   :source-code: policy/misc/scan.zeek 37 37

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 mins``

   Failed connection attempts are tracked over this time interval for
   the address scan detection.  A higher interval will detect slower
   scanners, but may also yield more false positives.

.. zeek:id:: Scan::addr_scan_threshold
   :source-code: policy/misc/scan.zeek 46 46

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``25.0``

   The threshold of the unique number of hosts a scanning host has to
   have failed connections with on a single port.

.. zeek:id:: Scan::port_scan_interval
   :source-code: policy/misc/scan.zeek 42 42

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5.0 mins``

   Failed connection attempts are tracked over this time interval for
   the port scan detection.  A higher interval will detect slower
   scanners, but may also yield more false positives.

.. zeek:id:: Scan::port_scan_threshold
   :source-code: policy/misc/scan.zeek 50 50

   :Type: :zeek:type:`double`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0``

   The threshold of the number of unique ports a scanning host has to
   have failed connections with on a single victim host.

Hooks
#####
.. zeek:id:: Scan::addr_scan_policy
   :source-code: policy/misc/scan.zeek 52 52

   :Type: :zeek:type:`hook` (scanner: :zeek:type:`addr`, victim: :zeek:type:`addr`, scanned_port: :zeek:type:`port`) : :zeek:type:`bool`


.. zeek:id:: Scan::port_scan_policy
   :source-code: policy/misc/scan.zeek 53 53

   :Type: :zeek:type:`hook` (scanner: :zeek:type:`addr`, victim: :zeek:type:`addr`, scanned_port: :zeek:type:`port`) : :zeek:type:`bool`



