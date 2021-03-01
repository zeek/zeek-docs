:tocdepth: 3

base/bif/plugins/Zeek_SteppingStone.events.bif.zeek
===================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================= ==============================================
:zeek:id:`stp_correlate_pair`: :zeek:type:`event` Event internal to the stepping stone detector.
:zeek:id:`stp_create_endp`: :zeek:type:`event`    Deprecated.
:zeek:id:`stp_remove_endp`: :zeek:type:`event`    Event internal to the stepping stone detector.
:zeek:id:`stp_remove_pair`: :zeek:type:`event`    Event internal to the stepping stone detector.
:zeek:id:`stp_resume_endp`: :zeek:type:`event`    Event internal to the stepping stone detector.
================================================= ==============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: stp_correlate_pair
   :source-code: base/bif/plugins/Zeek_SteppingStone.events.bif.zeek 15 15

   :Type: :zeek:type:`event` (e1: :zeek:type:`int`, e2: :zeek:type:`int`)

   Event internal to the stepping stone detector.

.. zeek:id:: stp_create_endp
   :source-code: base/bif/plugins/Zeek_SteppingStone.events.bif.zeek 5 5

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, e: :zeek:type:`int`, is_orig: :zeek:type:`bool`)

   Deprecated. Will be removed.

.. zeek:id:: stp_remove_endp
   :source-code: base/bif/plugins/Zeek_SteppingStone.events.bif.zeek 23 23

   :Type: :zeek:type:`event` (e: :zeek:type:`int`)

   Event internal to the stepping stone detector.

.. zeek:id:: stp_remove_pair
   :source-code: base/bif/plugins/Zeek_SteppingStone.events.bif.zeek 19 19

   :Type: :zeek:type:`event` (e1: :zeek:type:`int`, e2: :zeek:type:`int`)

   Event internal to the stepping stone detector.

.. zeek:id:: stp_resume_endp
   :source-code: base/bif/plugins/Zeek_SteppingStone.events.bif.zeek 11 11

   :Type: :zeek:type:`event` (e: :zeek:type:`int`)

   Event internal to the stepping stone detector.


