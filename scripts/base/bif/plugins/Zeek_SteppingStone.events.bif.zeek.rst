:tocdepth: 3

base/bif/plugins/Zeek_SteppingStone.events.bif.zeek
===================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================================================== ==============================================
:zeek:id:`stp_correlate_pair`: :zeek:type:`event` :zeek:attr:`&deprecated` = *...* Event internal to the stepping stone detector.
:zeek:id:`stp_create_endp`: :zeek:type:`event` :zeek:attr:`&deprecated` = *...*    Deprecated.
:zeek:id:`stp_remove_endp`: :zeek:type:`event` :zeek:attr:`&deprecated` = *...*    Event internal to the stepping stone detector.
:zeek:id:`stp_remove_pair`: :zeek:type:`event` :zeek:attr:`&deprecated` = *...*    Event internal to the stepping stone detector.
:zeek:id:`stp_resume_endp`: :zeek:type:`event` :zeek:attr:`&deprecated` = *...*    Event internal to the stepping stone detector.
================================================================================== ==============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: stp_correlate_pair

   :Type: :zeek:type:`event` (e1: :zeek:type:`int`, e2: :zeek:type:`int`)
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v4.1. The stepping-stone analyzer has been unmaintained for a long time and will be removed. See ticket 1573 for details"*

   Event internal to the stepping stone detector.

.. zeek:id:: stp_create_endp

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, e: :zeek:type:`int`, is_orig: :zeek:type:`bool`)
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v4.1. The stepping-stone analyzer has been unmaintained for a long time and will be removed. See ticket 1573 for details"*

   Deprecated. Will be removed.

.. zeek:id:: stp_remove_endp

   :Type: :zeek:type:`event` (e: :zeek:type:`int`)
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v4.1. The stepping-stone analyzer has been unmaintained for a long time and will be removed. See ticket 1573 for details"*

   Event internal to the stepping stone detector.

.. zeek:id:: stp_remove_pair

   :Type: :zeek:type:`event` (e1: :zeek:type:`int`, e2: :zeek:type:`int`)
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v4.1. The stepping-stone analyzer has been unmaintained for a long time and will be removed. See ticket 1573 for details"*

   Event internal to the stepping stone detector.

.. zeek:id:: stp_resume_endp

   :Type: :zeek:type:`event` (e: :zeek:type:`int`)
   :Attributes: :zeek:attr:`&deprecated` = *"Remove in v4.1. The stepping-stone analyzer has been unmaintained for a long time and will be removed. See ticket 1573 for details"*

   Event internal to the stepping stone detector.


