
.. image:: /images/zeek-logo-text.png
   :align: center
   :scale: 100%

==================
Zeek Documentation
==================

.. important::

  Make sure to read the :ref:`appropriate documentation version
  <documentation-versioning>`.

The purpose of this document is to assist the Zeek community with implementing
Zeek in their environments. The document includes material on Zeek's unique
capabilities, how to install it, how to interpret the default logs that Zeek
generates, and how to modify Zeek to fit your needs. The document is the
result of a volunteer community effort. If you would like to contribute, or
want more information, please visit the `Zeek web page
<https://zeek.org/getting-started-in-the-zeek-community/>`_ for details on how
to connect with the community.

.. toctree::
   :maxdepth: 2
   :caption: Table of Contents

   about
   monitoring
   get-started
   log-formats
   logs/index
   scripting/index
   frameworks/index
   script-reference/index
   devel/index
   components/index
   acknowledgements

:ref:`General Index <genindex>`

.. _documentation-versioning:

Documentation Versioning
========================

.. attention::

  The Zeek codebase has three primary branches of interest to users and
  this document is also maintained as three different versions, one
  associated with each branch of Zeek.  The default version of
  `docs.zeek.org <https://docs.zeek.org>`_ tracks the latest Zeek release:

    * Current Feature Release: https://docs.zeek.org/en/current

  If you instead use a Zeek Long-Term Support (LTS) release or
  Git *master* branch, these are the appropriate starting points:

    * Long-Term Support Release: https://docs.zeek.org/en/lts
    * Git *master* Branch: https://docs.zeek.org/en/master

  To help clarify which release you are using, the version numbering
  scheme for the two release branches is described in the `Release
  Cadence <https://github.com/zeek/zeek/wiki/Release-Cadence>`_ policy.
