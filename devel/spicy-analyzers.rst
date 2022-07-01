============================
Writing analyzers with Spicy
============================

`Spicy <https://docs.zeek.org/projects/spicy/en/latest/index.html>`_ is a
parser generator that makes it easy to create robust C++ parsers network
protocols, file formats, and more. Spicy analyzers can be integrated with Zeek
with `spicy-plugin <https://github.com/zeek/spicy-plugin>`_ so that one can
create Zeek protocol, packet and file analyzers.

Spicy is documented separately, so this section just presents high-level points
relevant for Zeek.

Installation
============

A Zeek configured with default ``./configure`` options includes Spicy. If the
``--disable-spicy`` configure option is used instead, Spicy and
``spicy-plugin`` need to be installed out of band, see the `instructions for
Spicy <https://docs.zeek.org/projects/spicy/en/latest/installation.html>`_ and
`spicy-plugin <https://github.com/zeek/spicy-plugin>`_, respectively.

Writing an analyzer
===================

Analyzer scaffolding including a Spicy grammar ``.spicy``, Zeek integration
glue code ``.evt`` and a CMake build setup can be generated with the `zkg
package manager <https://docs.zeek.org/projects/package-manager>`_ with the
default package template by passing ``--feature spicy-analyzer``.

See the `Spicy documentation <https://docs.zeek.org/projects/spicy/en/latest/getting-started.html>`_
for details on how to write and integrate a parser.
