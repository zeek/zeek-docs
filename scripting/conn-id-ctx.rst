
.. _script-conn-id-ctx:

==============================
Use of :zeek:see:`conn_id_ctx`
==============================

.. versionadded:: 8.0

.. note::

   We’re still iterating on patterns for working with the new pluggable
   connection keys and :zeek:see:`conn_id_ctx` instances.
   If you have feedback or run into limitations for your use-cases, please reach out!

In certain deployments, Zeek will receive network traffic from different
network segments that may have overlapping IP ranges.
For example, host 10.0.0.37 in segment A and host 10.0.0.37 in segment B
share the same IP address, but represent different systems.
The terminology used within Zeek is that IP addresses or connections
are observed in different "contexts".


Commonly, ethernet layers may contain information that makes it possible to discriminate
between different network segments. Concretely, VLAN tagging is one such approach.
Segments can also be distinguished by Virtual Network Identifiers (VNIs)
in case of UDP-based tunnels like VXLAN or Geneve.


Since Zeek 8.0, this information can be extracted by
:ref:`plugin-provided connection key implementations <connkey-plugin>`
and included into Zeek's core connection tracking. Further, plugins
:zeek:keyword:`redefine <redef>` :zeek:see:`conn_id_ctx` with additional
fields to expose the extracted information used for connection tracking to
the Zeek scripting layer.
For example, loading the doc:`/scripts/policy/frameworks/conn_key/vlan_fivetuple.zeek`
adds :zeek:field:`vlan` and :zeek:field:`inner_vlan` fields to :zeeK:see:`conn_id_ctx`.

Script writers can use the :zeek:field:`conn_id$ctx <conn_id$ctx>` field to
discriminate the same :zeek:type:`addr` values observed in different contexts.

For example, to count the number of connections per originator address in
a context-aware manner, add the :zeek:see:`conn_id_ctx` instance as part
of the index into a table:

.. code-block:: zeek

	global connection_counts: table[conn_id_ctx, addr] of count &default=0;

	event new_connection(c: connection) {
		++connection_counts[c$id$ctx, c$id$orig_h];
	}


If :zeek:field:`ctx` is populated with fields for VLAN tags, the table indexing
will take them into account and create individual entries per ``(ctx, addr)``
pair.


Alternatively, users can define their own record type that includes both :zeek:see:`conn_id_ctx` and :zeek:type:`addr`,
and use instances of such records to index into tables.

.. literalinclude:: conn_id_ctx_my_endpoint.zeek
   :caption: conn_id_ctx_my_endpoint.zeek
   :language: zeek
   :linenos:
   :tab-width: 4

This example tracks services that an originator IP address has been observed to interact with.
When loading the doc:`/scripts/policy/frameworks/conn_key/vlan_fivetuple.zeek`
script, IP addresses in different VLANs are tracked separately:

.. code-block:: shell

    $ zeek -r vlan-collisions.pcap frameworks/conn_key/vlan_fivetuple conn_id_ctx_my_endpoint.zeek
    [ctx=[vlan=42, inner_vlan=<uninitialized>], a=141.142.228.5], HTTP
    [ctx=[vlan=10, inner_vlan=20], a=141.142.228.5], HTTP
    [ctx=[vlan=<uninitialized>, inner_vlan=<uninitialized>], a=141.142.228.5], HTTP


Note that this script snippet isn't VLAN-specific, yet it is VLAN-aware. When
using a different connection key plugin, like the one discussed in the
:ref:`connection key tutorial <connkey-plugin>`, the result is as follows instead,
discriminating entries in the ``talks_with_service`` table by the value of
``c$id$ctx$vxlan_vni``.

.. code-block:: shell

    $ zeek -C -r vxlan-overlapping-http-get.pcap  ConnKey::factory=ConnKey::CONNKEY_VXLAN_VNI_FIVETUPLE conn_id_ctx_my_endpoint.zeek
    [ctx=[vxlan_vni=<uninitialized>], a=141.142.228.5], HTTP
    [ctx=[vxlan_vni=<uninitialized>], a=127.0.0.1], VXLAN
    [ctx=[vxlan_vni=4711], a=141.142.228.5], HTTP
    [ctx=[vxlan_vni=4242], a=141.142.228.5], HTTP


When using Zeek's default five-tuple hashing instead, the :zeek:see:`conn_id_ctx`
record is empty and address 141.142,228.5 maps to a single entry in the table:

.. code-block:: shell

    $ zeek -C -r vxlan-overlapping-http-get.pcap conn_id_ctx_my_endpoint.zeek
    [ctx=[], a=141.142.228.5], HTTP
    [ctx=[], a=127.0.0.1], VXLAN
