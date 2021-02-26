:tocdepth: 3

base/utils/site.zeek
====================
.. zeek:namespace:: Site

Definitions describing a site - which networks and DNS zones are "local"
and "neighbors", and servers running particular services.

:Namespace: Site
:Imports: :doc:`base/utils/patterns.zeek </scripts/base/utils/patterns.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================ ======================================================================
:zeek:id:`Site::local_admins`: :zeek:type:`table` :zeek:attr:`&redef`        If local network administrators are known and they have responsibility
                                                                             for defined address space, then a mapping can be defined here between
                                                                             networks for which they have responsibility and a set of email
                                                                             addresses.
:zeek:id:`Site::local_nets`: :zeek:type:`set` :zeek:attr:`&redef`            Networks that are considered "local".
:zeek:id:`Site::local_zones`: :zeek:type:`set` :zeek:attr:`&redef`           DNS zones that are considered "local".
:zeek:id:`Site::neighbor_nets`: :zeek:type:`set` :zeek:attr:`&redef`         Networks that are considered "neighbors".
:zeek:id:`Site::neighbor_zones`: :zeek:type:`set` :zeek:attr:`&redef`        DNS zones that are considered "neighbors".
:zeek:id:`Site::private_address_space`: :zeek:type:`set` :zeek:attr:`&redef` Address space that is considered private and unrouted.
============================================================================ ======================================================================

State Variables
###############
===================================================== =====================================================================
:zeek:id:`Site::local_nets_table`: :zeek:type:`table` This is used for retrieving the subnet when using multiple entries in
                                                      :zeek:id:`Site::local_nets`.
===================================================== =====================================================================

Functions
#########
======================================================== =================================================================
:zeek:id:`Site::get_emails`: :zeek:type:`function`       Function that returns a comma-separated list of email addresses
                                                         that are considered administrators for the IP address provided as
                                                         an argument.
:zeek:id:`Site::is_local_addr`: :zeek:type:`function`    Function that returns true if an address corresponds to one of
                                                         the local networks, false if not.
:zeek:id:`Site::is_local_name`: :zeek:type:`function`    Function that returns true if a host name is within a local
                                                         DNS zone.
:zeek:id:`Site::is_neighbor_addr`: :zeek:type:`function` Function that returns true if an address corresponds to one of
                                                         the neighbor networks, false if not.
:zeek:id:`Site::is_neighbor_name`: :zeek:type:`function` Function that returns true if a host name is within a neighbor
                                                         DNS zone.
:zeek:id:`Site::is_private_addr`: :zeek:type:`function`  Function that returns true if an address corresponds to one of
                                                         the private/unrouted networks, false if not.
======================================================== =================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Site::local_admins
   :source-code: base/utils/site.zeek 38 38

   :Type: :zeek:type:`table` [:zeek:type:`subnet`] of :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   If local network administrators are known and they have responsibility
   for defined address space, then a mapping can be defined here between
   networks for which they have responsibility and a set of email
   addresses.

.. zeek:id:: Site::local_nets
   :source-code: base/utils/site.zeek 22 22

   :Type: :zeek:type:`set` [:zeek:type:`subnet`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Networks that are considered "local".  Note that ZeekControl sets
   this automatically.

.. zeek:id:: Site::local_zones
   :source-code: base/utils/site.zeek 41 41

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   DNS zones that are considered "local".

.. zeek:id:: Site::neighbor_nets
   :source-code: base/utils/site.zeek 32 32

   :Type: :zeek:type:`set` [:zeek:type:`subnet`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Networks that are considered "neighbors".

.. zeek:id:: Site::neighbor_zones
   :source-code: base/utils/site.zeek 44 44

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   DNS zones that are considered "neighbors".

.. zeek:id:: Site::private_address_space
   :source-code: base/utils/site.zeek 10 10

   :Type: :zeek:type:`set` [:zeek:type:`subnet`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            ::1/128,
            fe80::/10,
            192.168.0.0/16,
            172.16.0.0/12,
            10.0.0.0/8,
            127.0.0.0/8,
            100.64.0.0/10
         }


   Address space that is considered private and unrouted.
   By default it has RFC defined non-routable IPv4 address space.

State Variables
###############
.. zeek:id:: Site::local_nets_table
   :source-code: base/utils/site.zeek 29 29

   :Type: :zeek:type:`table` [:zeek:type:`subnet`] of :zeek:type:`subnet`
   :Default: ``{}``

   This is used for retrieving the subnet when using multiple entries in
   :zeek:id:`Site::local_nets`.  It's populated automatically from there.
   A membership query can be done with an
   :zeek:type:`addr` and the table will yield the subnet it was found
   within.

Functions
#########
.. zeek:id:: Site::get_emails
   :source-code: base/utils/site.zeek 146 149

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`string`

   Function that returns a comma-separated list of email addresses
   that are considered administrators for the IP address provided as
   an argument.
   The function inspects :zeek:id:`Site::local_admins`.

.. zeek:id:: Site::is_local_addr
   :source-code: base/utils/site.zeek 83 86

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Function that returns true if an address corresponds to one of
   the local networks, false if not.
   The function inspects :zeek:id:`Site::local_nets`.

.. zeek:id:: Site::is_local_name
   :source-code: base/utils/site.zeek 98 101

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`bool`

   Function that returns true if a host name is within a local
   DNS zone.
   The function inspects :zeek:id:`Site::local_zones`.

.. zeek:id:: Site::is_neighbor_addr
   :source-code: base/utils/site.zeek 88 91

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Function that returns true if an address corresponds to one of
   the neighbor networks, false if not.
   The function inspects :zeek:id:`Site::neighbor_nets`.

.. zeek:id:: Site::is_neighbor_name
   :source-code: base/utils/site.zeek 103 106

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`bool`

   Function that returns true if a host name is within a neighbor
   DNS zone.
   The function inspects :zeek:id:`Site::neighbor_zones`.

.. zeek:id:: Site::is_private_addr
   :source-code: base/utils/site.zeek 93 96

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`bool`

   Function that returns true if an address corresponds to one of
   the private/unrouted networks, false if not.
   The function inspects :zeek:id:`Site::private_address_space`.


