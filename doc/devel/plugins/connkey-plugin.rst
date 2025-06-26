.. _connkey-plugin:

===============================
Writing a Connection Key Plugin
===============================

.. versionadded:: 8.0

Zeek's plugin API allows adding support for custom connection keys. By default,
Zeek uses connection keys based on the classic five tuple consisting of IP addresses,
port pairs and the protocol identifier.
In certain environments, the classic five tuple alone is not sufficient to discriminate
between different connections.
One such example is Zeek receiving mirrored traffic from different VLANs that
have overlapping IP ranges.
Concretely, a connection between 10.0.0.1 and 10.0.0.2 in one VLAN is
distinct from a connection between the same IPs in another VLAN.
Here, Zeek should include the VLAN identifier into the connection key.

This document describes how to provide custom connection keys to Zeek in
form of a tutorial.
If you're not familiar with plugin development, head over to the
:ref:`Writing Plugins <writing-plugins>` section.

Our goal is to implement a custom connection key to scope connections
transported within a `VXLAN <https://datatracker.ietf.org/doc/html/rfc7348/index.html>`_
tunnel by the VXLAN Network Identifier (VNI).

As a test case, the `HTTP GET trace <https://github.com/zeek/zeek/raw/refs/heads/master/testing/btest/Traces/http/get.trace>`_ from the Zeek
repository is encapsulated twice with VXLAN using VNIs 4711 and 4242, respectively.
We merge the resulting two PCAP files with the original PCAP.
The :download:`resulting PCAP <connkey-vxlan-fivetuple-plugin-src/Traces/vxlan-overlapping-http-get.pcap>` technically contains three individual HTTP connections, two of which
are VXLAN encapsulated.

By default, Zeek will create the same connection key for the original and
encapsulated HTTP connections as they have identical inner five tuples.
Therefore, only a single ``http.log`` entry and two ``conn.log`` entries
are created.

.. code-block:: shell

    $ zeek -C -r Traces/vxlan-overlapping-http-get.pcap
    $ zeek-cut -m uid method host uri < http.log
    uid     method  host    uri
    CpWF5etn1l2rpaLu3       GET     bro.org /download/CHANGES.bro-aux.txt

    $ zeek-cut -m uid service history orig_pkts resp_pkts < conn.log
    uid     service history orig_pkts       resp_pkts
    Cq2CY245oGGbibJ8k9      http    ShADTadtFf      21      21
    CMleDu4xANIMzePYd7      vxlan   D       28      0

Note that just two of the HTTP connections are encapsulated.
That is why the VXLAN connection shows only 28 packets.
Each HTTP connection has 14 packets total, 7 in each direction. All are
aggregated into the single HTTP connection, but only 28 of these packets were
transported within the VXLAN tunnel connection. Note also the ``t`` and ``T``
flags in the :zeek:field:`Conn::Info$history` field. These stand for retransmissions
and caused by Zeek not discriminating between the different HTTP connections.

The plugin we'll be developing adds the VXLAN VNI to the connection key.
The result is that instead of a single HTTP connection, there'll be three HTTP
connections tracked and logged separately by Zeek. The VNI is also added as
:zeek:field:`vxlan_vni` to the :zeek:see:`conn_id` record and therefore available
in the ``http.log`` and ``conn.log`` as part of the ``id.*`` fields.

The logs after activating the plugin will change and look as follows:

.. code-block:: shell

    $ zeek-cut -m uid method host uri id.vxlan_vni < http.log
    uid     method  host    uri     id.vxlan_vni
    CyZiAc2lEt5DAZseQl      GET     bro.org /download/CHANGES.bro-aux.txt   4711
    CIwCdr1G7sTtHRZ8y4      GET     bro.org /download/CHANGES.bro-aux.txt   4242
    CWBNgn3JYHzXJZjXKc      GET     bro.org /download/CHANGES.bro-aux.txt   -

    $ zeek-cut -m uid service history orig_pkts resp_pkts id.vxlan_vni < conn.log
    uid     service history orig_pkts       resp_pkts       id.vxlan_vni
    CWBNgn3JYHzXJZjXKc      http    ShADadFf        7       7       -
    CIwCdr1G7sTtHRZ8y4      http    ShADadFf        7       7       4242
    CyZiAc2lEt5DAZseQl      http    ShADadFf        7       7       4711
    C24p8iCAjprR6LFn8       vxlan   D       28      0       -


Implementation
==============

Adding alternative connection keys involves implementing two classes.
First, a factory class producing ``zeek::ConnKey`` instances. This
is the class created through the added ``zeek::conn_key::Component``.
Second, a custom connection key class derived from ``zeek::ConnKey``.
Instances of this class are created by the factory. This is a typical
abstract factory pattern.

Our plugin's ``Configure()`` method follows the standard pattern of setting up
basic information about the plugin and then registering the ``ConnKey`` component.

.. literalinclude:: connkey-vxlan-fivetuple-plugin-src/src/Plugin.cc
   :caption: Plugin.cc
   :language: cpp
   :lines: 16-
   :linenos:
   :tab-width: 4


Next, in the ``Factory.cc`` file, we're implementing a custom ``zeek::ConnKey`` class.
This class is named ``VxlanVniConnKey`` and inherits from ``zeek::IPBasedConnKey``.
While ``zeek::ConnKey`` is technically the base class, in this tutorial we'll
derive from ``zeek::IPBasedConnKey``.
Currently, Zeek only supports IP-based connection tracking via the
``IPBasedAnalyzer`` analyzer. This analyzer requires ``zeek::IPBasedConnKey``
instances.

.. literalinclude:: connkey-vxlan-fivetuple-plugin-src/src/Factory.cc
   :caption: VxlanVniConnKey class in Factory.cc
   :language: cpp
   :linenos:
   :lines: 18-71
   :tab-width: 4

The current pattern for custom connection keys is to embed the bytes used for
the ``zeek::session::detail::Key`` as a packed struct within a ``ConnKey`` instance.
We override ``DoPopulateConnIdVal()`` to set the :zeek:field:`vxlan_vni` field
of a :zeek:see:`conn_id` record value to the extracted VXLAN VNI. A small trick
employed is that we default the most significant byte of ``vxlan_vni`` to 0xFF.
As a VNI is only 24bit, this allows us to determine if a VNI was actually
extracted, or whether it is unset.

The ``DoInit()`` implementation is the actual place for connection key customization.
This is where we extract the VXLAN VNI. To do so, we're using the relatively
new ``GetAnalyzerData()`` API of the packet analysis manager.
This API allows generic access to the layers analyzed for  give packet analyzer.
For our use-case, we take the most outer VXLAN layer, if any, and extract the VNI
into ``key.vxlan_vni``.

There's no requirement to use the ``GetAnalyzerData()`` API. If the ``zeek::Packet``
instance passed to ``DoInit()`` contains the needed information, e.g. VLAN identifiers
or information from the packet's raw bytes, they can be used directly.
Specifically, ``GetAnalyzerData()`` may introduce additional overhead into the
packet path that can be avoided if the needed information is available
already elsewhere.
Using other Zeek APIs ways to determine connection key information is of
course also possible.

The next part shown concerns the ``Factory`` class itself. The
``DoConnKeyFromVal()`` method contains logic to produce a ``VxlanVniConnKey``
instance from an existing :zeek:see:`conn_id` record.
This is needed in order for the :zeek:see:`lookup_connection` builtin function to work properly.
The implementation re-uses the ``DoConnKeyFromVal()`` implementation of the
default ``fivetuple::Factory`` that our factory inherits from to extract the
classic five tuple information.

.. literalinclude:: connkey-vxlan-fivetuple-plugin-src/src/Factory.cc
   :caption: Factory class in Factory.cc
   :language: cpp
   :linenos:
   :lines: 73-95
   :tab-width: 4


Last, the plugin's ``__load__.zeek`` file is shown. It includes the extension
of the :zeek:see:`conn_id` identifier by the :zeek:field:`vxlan_vni` field.

.. literalinclude:: connkey-vxlan-fivetuple-plugin-src/scripts/__load__.zeek
   :caption: The conn_id redefinition in __load__.zeek
   :language: zeek
   :linenos:
   :tab-width: 4


Using the custom Connection Key
===============================

After installing the plugin, the new connection key implementation can be
selected by redefining the script-level :zeek:see:`ConnKey::factory` variable.
This can either be done in a separate script, but we do it directly on the
command-line for simplicity. The ``ConnKey::CONNKEY_VXLAN_VNI_FIVETUPLE`` is
registered in Zeek during the plugin's ``AddComponent()`` call during
``Configure()``, where the component has the name ``VXLAN_VNI_FIVETUPLE``.

.. code-block:: shell

    $ zeek -C -r Traces/vxlan-overlapping-http-get.pcap  ConnKey::factory=ConnKey::CONNKEY_VXLAN_VNI_FIVETUPLE


Viewing the ``conn.log`` now shows three separate HTTP connections,
two of which have a ``vxlan_vni`` value set in their logs.


.. code-block:: shell

    $ zeek-cut -m uid service history orig_pkts resp_pkts id.vxlan_vni < conn.log
    uid     service history orig_pkts       resp_pkts       id.vxlan_vni
    CWBNgn3JYHzXJZjXKc      http    ShADadFf        7       7       -
    CIwCdr1G7sTtHRZ8y4      http    ShADadFf        7       7       4242
    CyZiAc2lEt5DAZseQl      http    ShADadFf        7       7       4711
    C24p8iCAjprR6LFn8       vxlan   D       28      0       -

Pretty cool, isn't it?
