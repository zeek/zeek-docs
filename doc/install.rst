
.. _CMake: https://www.cmake.org
.. _SWIG: http://www.swig.org
.. _Xcode: https://developer.apple.com/xcode/
.. _MacPorts: http://www.macports.org
.. _Fink: http://www.finkproject.org
.. _Homebrew: https://brew.sh
.. _downloads page: https://zeek.org/get-zeek
.. _devtoolset: https://developers.redhat.com/products/developertoolset/hello-world
.. _zkg package manager: https://docs.zeek.org/projects/package-manager/en/stable/
.. _crosstool-NG: https://crosstool-ng.github.io/
.. _CMake toolchain: https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html
.. _contribute: https://github.com/zeek/zeek/wiki/Contribution-Guide

.. _installing-zeek:

===============
Installing Zeek
===============

Prerequisites
=============

Before installing Zeek, you'll need to ensure that some dependencies
are in place.

Required Dependencies
---------------------

Zeek requires the following libraries and tools to be installed
before you begin:

    * Libpcap                           (http://www.tcpdump.org)
    * OpenSSL libraries                 (https://www.openssl.org)
    * BIND8 library
    * Libz
    * Bash (for ZeekControl)
    * Python 3.5 or greater             (https://www.python.org/)

To build Zeek from source, the following additional dependencies are required:

    * CMake 3.5 or greater              (https://www.cmake.org)
    * Make
    * C/C++ compiler with C++17 support (GCC 7+ or Clang 4+)
    * SWIG                              (http://www.swig.org)
    * Bison 2.5 or greater              (https://www.gnu.org/software/bison/)
    * Flex (lexical analyzer generator) (https://github.com/westes/flex)
    * Libpcap headers                   (http://www.tcpdump.org)
    * OpenSSL headers                   (http://www.openssl.org)
    * zlib headers                      (https://zlib.net/)
    * Python 3.5 or greater             (https://www.python.org/)

To install the required dependencies, you can use:

* RPM/RedHat-based Linux:

  .. code-block:: console

     sudo yum install cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel python3 python3-devel swig zlib-devel

  Additionally, on RHEL/CentOS 7, you can install and activate a devtoolset_ to get access
  to recent GCC versions. You will also have to install and activate CMake 3.
  For example:

  .. code-block:: console

     sudo yum install cmake3 devtoolset-7
     scl enable devtoolset-7 bash

* DEB/Debian-based Linux:

  .. code-block:: console

     sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev

* FreeBSD:

  Most required dependencies should come with a minimal FreeBSD install
  except for the following.

  .. code-block:: console

      sudo pkg install -y bash git cmake swig bison python3 base64
      pyver=`python3 -c 'import sys; print(f"py{sys.version_info[0]}{sys.version_info[1]}")'`
      sudo pkg install -y $pyver-sqlite3

* macOS:

  Compiling source code on Macs requires first installing either Xcode_
  or the "Command Line Tools" (which is a much smaller download).  To check
  if either is installed, run the ``xcode-select -p`` command.  If you see
  an error message, then neither is installed and you can then run
  ``xcode-select --install`` which will prompt you to either get Xcode (by
  clicking "Get Xcode") or to install the command line tools (by
  clicking "Install").

  macOS comes with all required dependencies except for CMake_, SWIG_,
  Bison, and OpenSSL (OpenSSL headers were removed in macOS 10.11,
  therefore OpenSSL must be installed manually for macOS versions 10.11
  or newer).

  Distributions of these dependencies can likely be obtained from your
  preferred macOS package management system (e.g. Homebrew_,
  MacPorts_, or Fink_). Specifically for Homebrew, the ``cmake``,
  ``swig``, ``openssl``, and ``bison`` packages
  provide the required dependencies.  For MacPorts, the ``cmake``,
  ``swig``, ``swig-python``, ``openssl``, and ``bison`` packages provide
  the required dependencies.

Optional Dependencies
---------------------

Zeek can make use of some optional libraries and tools if they are found at
build time:

    * libmaxminddb (for geolocating IP addresses)
    * sendmail (enables Zeek and ZeekControl to send mail)
    * curl (used by a Zeek script that implements active HTTP)
    * gperftools (tcmalloc is used to improve memory and CPU usage)
    * jemalloc (https://github.com/jemalloc/jemalloc)
    * PF_RING (Linux only, see :ref:`pf-ring-config`)
    * krb5 libraries and headers
    * ipsumdump (for trace-summary; https://github.com/kohler/ipsumdump)

Geolocation is probably the most interesting and can be installed
on most platforms by following the instructions for :ref:`installing
the GeoIP library and database
<geolocation>`.

The `zkg package manager`_, included in the Zeek installation, requires
two external Python modules:

    * GitPython: https://pypi.org/project/GitPython/
    * semantic-version: https://pypi.org/project/semantic-version/

These install easily via pip (``pip3 install GitPython
semantic-version``) and ship with some distributions:

* RPM/RedHat-based Linux:

  .. code-block:: console

     sudo yum install python3-GitPython python3-semantic_version

* DEB/Debian-based Linux:

  .. code-block:: console

     sudo apt-get install python3-git python3-semantic-version


Installing Zeek
===============

Zeek can be downloaded as either pre-built binary packages for Linux, or in
source code form. On many platforms, Zeek also comes already integrated into
package management systems (e.g., Homebrew on macOS), Note, however, that such
external packages may not always be fully up to date.

Using Pre-Built Binary Release Packages for Linux
-------------------------------------------------

We are providing prebuilt binary packages for a variety of Linux distributions.
See the `Binary-Packages wiki
<https://github.com/zeek/zeek/wiki/Binary-Packages>`_ for the latest updates on
binary releases and for more information.

You can download the `packages for the latest feature release build here
<https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek>`_
for all the supported distributions. Please follow the instructions on that
link to add rpm/deb repositories for the corresponding OS; grabbing the binary
files directly does not give you all dependencies. The `package source files are
available here <https://build.opensuse.org/package/show/security:zeek/zeek>`_.

As an example, for CentOS:

  For CentOS 8 run the following as root:

  .. code-block:: console

     cd /etc/yum.repos.d/
     wget https://download.opensuse.org/repositories/security:zeek/CentOS_8/security:zeek.repo
     yum install zeek

  For CentOS 7 run the following as root:

  .. code-block:: console

     cd /etc/yum.repos.d/
     wget https://download.opensuse.org/repositories/security:zeek/CentOS_7/security:zeek.repo
     yum install zeek

Furthermore, you can download the `packages for the latest LTS release build
here
<https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-lts>`_
and `nightly builds are also available here
<https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-nightly>`_
for all the supported operating systems. Please follow the instructions on the
links to add rpm/deb repositories for the corresponding OS; grabbing the binary
files directly does not give you all dependencies. The `source files for LTS
builds are available here
<https://build.opensuse.org/package/show/security:zeek/zeek-lts>`_ and for
nightly builds `source files are here
<https://build.opensuse.org/package/show/security:zeek/zeek-nightly>`_.

For example, if you prefer to use the most recent LTS release, use ``yum install
zeek-lts``, and for the nightly builds use ``yum install zeek-nightly`` instead.

The primary install prefix for binary packages is :file:`/opt/zeek` (depending
on which version you’re using).

Installing from Source
----------------------

Zeek releases are bundled into source packages for convenience and are
available on the `downloads page`_. The source code can be manually downloaded
from the link in the *tar.gz* format to the target system for installation.

If you plan to `contribute`_ to Zeek or just want to try out the latest
features under development, you should obtain Zeek's source code through its
Git repositories hosted at https://github.com/zeek:

.. code-block:: console

    git clone --recursive https://github.com/zeek/zeek

.. note:: If you choose to clone the ``zeek`` repository
   non-recursively for a "minimal Zeek experience", be aware that
   compiling it depends on several of the other submodules as well, so
   you'll likely have to build/install those independently first.

The typical way to build and install from source is (for more options,
run ``./configure --help``):

.. code-block:: console

    ./configure
    make
    make install

If the ``configure`` script fails, then it is most likely because it either
couldn't find a required dependency or it couldn't find a sufficiently new
version of a dependency.  Assuming that you already installed all required
dependencies, then you may need to use one of the ``--with-*`` options
that can be given to the ``configure`` script to help it locate a dependency.
To find out what all different options ``./configure`` supports, run
``./configure --help``.

The default installation path is ``/usr/local/zeek``, which would typically
require root privileges when doing the ``make install``.  A different
installation path can be chosen by specifying the ``configure`` script
``--prefix`` option.  Note that ``/usr``, ``/opt/bro/``, and ``/opt/zeek`` are
the standard prefixes for binary Zeek packages to be installed, so those are
typically not good choices unless you are creating such a package.

OpenBSD users, please see our `FAQ <https://zeek.org/faq/>`_ if you are having
problems installing Zeek.

Depending on the Zeek package you downloaded, there may be auxiliary
tools and libraries available in the ``auxil/`` directory. Some of them
will be automatically built and installed along with Zeek. There are
``--disable-*`` options that can be given to the configure script to
turn off unwanted auxiliary projects that would otherwise be installed
automatically.  Finally, use ``make install-aux`` to install some of
the other programs that are in the ``auxil/zeek-aux`` directory.

Finally, if you want to build the Zeek documentation (not required, because
all of the documentation for the latest Zeek release is available at
https://docs.zeek.org), there are instructions in ``doc/README`` in the source
distribution.

Cross Compiling
---------------

Prerequisites
~~~~~~~~~~~~~

You need three things on the host system:

1. The Zeek source tree.
2. A cross-compilation toolchain, such as one built via crosstool-NG_.
3. Pre-built Zeek dependencies from the target system.  This usually
   includes libpcap, zlib, OpenSSL, and Python development headers
   and libraries.

Configuration and Compiling
~~~~~~~~~~~~~~~~~~~~~~~~~~~

You first need to compile a few build tools native to the host system
for use during the later cross-compile build.  In the root of your
Zeek source tree:

.. code-block:: console

   ./configure --builddir=../zeek-buildtools
   ( cd ../zeek-buildtools && make binpac bifcl )

Next configure Zeek to use your cross-compilation toolchain (this example
uses a Raspberry Pi as the target system):

.. code-block:: console

   ./configure --toolchain=/home/jon/x-tools/RaspberryPi-toolchain.cmake --with-binpac=$(pwd)/../zeek-buildtools/auxil/binpac/src/binpac --with-bifcl=$(pwd)/../zeek-buildtools/src/bifcl

Here, the :file:`RaspberryPi-toolchain.cmake` file specifies a `CMake
toolchain`_.  In the toolchain file, you need to point the toolchain and
compiler at the cross-compilation toolchain.  It might look something the
following:

.. code-block:: cmake

  # Operating System on which CMake is targeting.
  set(CMAKE_SYSTEM_NAME Linux)

  # The CMAKE_STAGING_PREFIX option may not work.
  # Given that Zeek is configured:
  #
  #   `./configure --prefix=<dir>`
  #
  # The options are:
  #
  #   (1) `make install` and then copy over the --prefix dir from host to
  #       target system.
  #
  #   (2) `DESTDIR=<staging_dir> make install` and then copy over the
  #       contents of that staging directory.

  set(toolchain /home/jon/x-tools/arm-rpi-linux-gnueabihf)
  set(CMAKE_C_COMPILER   ${toolchain}/bin/arm-rpi-linux-gnueabihf-gcc)
  set(CMAKE_CXX_COMPILER ${toolchain}/bin/arm-rpi-linux-gnueabihf-g++)

  # The cross-compiler/linker will use these paths to locate dependencies.
  set(CMAKE_FIND_ROOT_PATH
      /home/jon/x-tools/zeek-rpi-deps
      ${toolchain}/arm-rpi-linux-gnueabihf/sysroot
  )

  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

If that configuration succeeds you are ready to build:

.. code-block:: console

   make

And if that works, install on your host system:

.. code-block:: console

   make install

Once installed, you can copy/move the files from the installation prefix on the
host system to the target system and start running Zeek as usual.

Configure the Run-Time Environment
==================================

You may want to adjust your :envvar:`PATH` environment variable
according to the platform/shell/package you're using since
neither :file:`/usr/local/zeek/bin/` or :file:`/opt/zeek/bin/`
are in the default :envvar:`PATH`. For example:

Bourne-Shell Syntax:

.. code-block:: console

   export PATH=/usr/local/zeek/bin:$PATH

C-Shell Syntax:

.. code-block:: console

   setenv PATH /usr/local/zeek/bin:$PATH

Or substitute ``/opt/zeek/bin`` instead if you installed from a binary package.
