
.. _upgrade-guidelines:

==============
How to Upgrade
==============

If you're doing an upgrade install (rather than a fresh install),
there's two suggested approaches: either install Zeek using the same
installation prefix directory as before, or pick a new prefix and copy
local customizations over.

In the following we summarize general guidelines for upgrading, see
the :ref:`release-notes` for version-specific information.


Reusing Previous Install Prefix
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you choose to configure and install Zeek with the same prefix
directory as before, first stop all running Zeek instances in your
cluster (if using ZeekControl, issue the "zeekctl stop" command on the
manager host).  Next, make a backup of the Zeek install prefix directory.

During the upgrade, any file in the install prefix may be
overwritten or removed, except for local customization of
files in the ``$prefix/share/zeek/site`` and ``$prefix/etc``
directories (``$prefix`` indicating the root
of where Zeek was installed).  Also, logs generated at run-time
won't be touched by the upgrade.

After upgrading, remember to check the ``$prefix/share/zeek/site`` and
``$prefix/etc`` directories for files with a file extension of ``.example``,
which indicate that the distribution's version of the file differs from the
local one, and therefore, may include local changes.  Review the
differences and make adjustments as necessary. Use the new version
for differences that aren't a result of a local change.

Finally, if using ZeekControl, then issue the "zeekctl deploy" command.  This
command will check for any policy script errors, install the new version
of Zeek to all machines in your cluster, and then it will start Zeek.

Using a New Install Prefix
~~~~~~~~~~~~~~~~~~~~~~~~~~

To install the newer version in a different prefix directory than before,
first stop all running Zeek instances in your cluster (if using ZeekControl,
then issue a "zeekctl stop" command on the manager host).  Next,
install the new version of Zeek in a new directory.

Next, copy local customization and configuration files
from the ``$prefix/share/zeek/site`` and ``$prefix/etc`` directories to the
new location (``$prefix`` indicating the root of where Zeek was originally
installed).  Review the files for differences
before copying and make adjustments as necessary (use the new version for
differences that aren't a result of a local change).  Of particular note,
the copied version of ``$prefix/etc/zeekctl.cfg`` is likely to need changes
to any settings that specify a pathname.

Finally, if using ZeekControl, then issue the "zeekctl deploy" command.  This
command will check for any policy script errors, install the new version
of Zeek to all machines in your cluster, and then it will start Zeek.
