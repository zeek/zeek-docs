:tocdepth: 3

policy/frameworks/management/persistence.zeek
=============================================

Common adjustments for any kind of Zeek node when we run the Management
framework.

:Imports: :doc:`base/misc/installation.zeek </scripts/base/misc/installation.zeek>`, :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`, :doc:`policy/frameworks/management/config.zeek </scripts/policy/frameworks/management/config.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================================================= =
:zeek:id:`Log::default_rotation_dir`: :zeek:type:`string` :zeek:attr:`&redef` 
============================================================================= =

Functions
#########
=============================================================== =
:zeek:id:`archiver_rotation_format_func`: :zeek:type:`function` 
=============================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: archiver_rotation_format_func
   :source-code: policy/frameworks/management/persistence.zeek 29 29

   :Type: :zeek:type:`function` (ri: :zeek:type:`Log::RotationFmtInfo`) : :zeek:type:`Log::RotationPath`



