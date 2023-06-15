============================
Writing analyzers with Spicy
============================

`Spicy <https://docs.zeek.org/projects/spicy/en/latest/index.html>`_ is a
parser generator that makes it easy to create robust C++ parsers for network
protocols, file formats, and more. Zeek supports integrating Spicy analyzers so
that one can create Zeek protocol, packet and file analyzers.

Spicy is documented separately, so this section just presents high-level points
relevant for Zeek.

Installation
============

A Zeek configured with default ``./configure`` options includes Spicy.

Writing an analyzer
===================

Analyzer scaffolding including a Spicy grammar ``.spicy``, Zeek integration
glue code ``.evt`` and a CMake build setup can be generated with the `zkg
package manager <https://docs.zeek.org/projects/package-manager>`_ with the
default package template by passing ``--features=spicy-protocol-analyzer``,
``--features=spicy-packet-analyzer``, or ``--features=spicy-file-analyzer`` to
create a Zeek protocol, packet, or file analyzer.

See the `Spicy documentation <https://docs.zeek.org/projects/spicy/en/latest/getting-started.html>`_
for details on how to write and integrate a parser.
