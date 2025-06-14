:tocdepth: 3

base/misc/version.zeek
======================
.. zeek:namespace:: Version

Provide information about the currently running Zeek version.  The most
convenient way to access this are the :zeek:see:`Version::number` and
:zeek:see:`Version::info` constants.

:Namespace: Version

Summary
~~~~~~~
Constants
#########
================================================================== ==========================================================================
:zeek:id:`Version::info`: :zeek:type:`Version::VersionDescription` :zeek:see:`Version::VersionDescription` record pertaining to the currently
                                                                   running version of Zeek.
:zeek:id:`Version::number`: :zeek:type:`count`                     version number of the currently running version of Zeek as a numeric
                                                                   representation.
================================================================== ==========================================================================

Types
#####
============================================================= ========================================
:zeek:type:`Version::VersionDescription`: :zeek:type:`record` A type exactly describing a Zeek version
============================================================= ========================================

Functions
#########
=================================================== ==================================================================
:zeek:id:`Version::at_least`: :zeek:type:`function` Test if the current running version of Zeek is greater or equal to
                                                    the given version string.
:zeek:id:`Version::parse`: :zeek:type:`function`    Parse a given version string.
=================================================== ==================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: Version::info
   :source-code: base/misc/version.zeek 123 123

   :Type: :zeek:type:`Version::VersionDescription`

   :zeek:see:`Version::VersionDescription` record pertaining to the currently
   running version of Zeek.

.. zeek:id:: Version::number
   :source-code: base/misc/version.zeek 130 130

   :Type: :zeek:type:`count`

   version number of the currently running version of Zeek as a numeric
   representation.  The format of the number is ABBCC with A being the
   major version, bb being the minor version (2 digits) and CC being the
   patchlevel (2 digits).  As an example, Zeek 2.4.1 results in the
   number 20401

Types
#####
.. zeek:type:: Version::VersionDescription
   :source-code: base/misc/version.zeek 9 38

   :Type: :zeek:type:`record`


   .. zeek:field:: version_number :zeek:type:`count`

      Number representing the version which can be used for easy comparison.
      The format of the number is ABBCC with A being the major version,
      bb being the minor version (2 digits) and CC being the patchlevel (2 digits).
      As an example, Zeek 2.4.1 results in the number 20401.


   .. zeek:field:: major :zeek:type:`count`

      Major version number (e.g. 2 for 2.5)


   .. zeek:field:: minor :zeek:type:`count`

      Minor version number (e.g. 5 for 2.5)


   .. zeek:field:: patch :zeek:type:`count`

      Patch version number (e.g. 0 for 2.5 or 1 for 2.4.1)


   .. zeek:field:: commit :zeek:type:`count`

      Commit number for development versions, Versions prior to 3.0.0,
      like "2.4-12", use a post-release commit number (12 commits
      after the 2.4 release).  Versions after 3.0.0, like
      "3.1.0-dev.37", use a pre-release commit number (37 commits
      into the development cycle for 3.1.0).  For non-development version
      this number will be zero.


   .. zeek:field:: beta :zeek:type:`bool`

      If set to true, the version is a beta build of Zeek.  These versions
      may start like "2.6-beta" or "3.0.0-rc" (the "rc" form started
      being used for 3.0.0 and later).


   .. zeek:field:: debug :zeek:type:`bool`

      If set to true, the version is a debug build


   .. zeek:field:: localversion :zeek:type:`string`

      Local version portion of the version string


   .. zeek:field:: version_string :zeek:type:`string`

      String representation of this version


   A type exactly describing a Zeek version

Functions
#########
.. zeek:id:: Version::at_least
   :source-code: base/misc/version.zeek 133 136

   :Type: :zeek:type:`function` (version_string: :zeek:type:`string`) : :zeek:type:`bool`

   Test if the current running version of Zeek is greater or equal to
   the given version string.
   

   :param version_string: Version to check against the current running version.
   

   :returns: True if running version greater or equal to the given version.

.. zeek:id:: Version::parse
   :source-code: base/misc/version.zeek 56 118

   :Type: :zeek:type:`function` (version_string: :zeek:type:`string`) : :zeek:type:`Version::VersionDescription`

   Parse a given version string.
   

   :param version_string: Zeek version string.
   

   :returns: :zeek:see:`Version::VersionDescription` record.


