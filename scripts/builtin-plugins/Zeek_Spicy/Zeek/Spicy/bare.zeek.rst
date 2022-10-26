:tocdepth: 3

builtin-plugins/Zeek_Spicy/Zeek/Spicy/bare.zeek
===============================================
.. zeek:namespace:: Spicy


:Namespace: Spicy
:Imports: :doc:`base/misc/version.zeek </scripts/base/misc/version.zeek>`

Summary
~~~~~~~
Functions
#########
================================================================== ===================================================================
:zeek:id:`Spicy::disable_file_analyzer`: :zeek:type:`function`     Disable a specific Spicy file analyzer if not already inactive.
:zeek:id:`Spicy::disable_protocol_analyzer`: :zeek:type:`function` Disable a specific Spicy protocol analyzer if not already inactive.
:zeek:id:`Spicy::enable_file_analyzer`: :zeek:type:`function`      Enable a specific Spicy file analyzer if not already active.
:zeek:id:`Spicy::enable_protocol_analyzer`: :zeek:type:`function`  Enable a specific Spicy protocol analyzer if not already active.
================================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Spicy::disable_file_analyzer
   :source-code: builtin-plugins/Zeek_Spicy/Zeek/Spicy/bare.zeek 79 82

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`bool`

   Disable a specific Spicy file analyzer if not already inactive. If
   this analyzer replaces an standard analyzer, that one will automatically
   be re-enabled.
   

   :tag: analyzer to toggle
   

   :returns: true if the operation succeeded

.. zeek:id:: Spicy::disable_protocol_analyzer
   :source-code: builtin-plugins/Zeek_Spicy/Zeek/Spicy/bare.zeek 68 71

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`) : :zeek:type:`bool`

   Disable a specific Spicy protocol analyzer if not already inactive. If
   this analyzer replaces an standard analyzer, that one will automatically
   be re-enabled.
   

   :tag: analyzer to toggle
   

   :returns: true if the operation succeeded

.. zeek:id:: Spicy::enable_file_analyzer
   :source-code: builtin-plugins/Zeek_Spicy/Zeek/Spicy/bare.zeek 74 77

   :Type: :zeek:type:`function` (tag: :zeek:type:`Files::Tag`) : :zeek:type:`bool`

   Enable a specific Spicy file analyzer if not already active. If this
   analyzer replaces an standard analyzer, that one will automatically be
   disabled.
   

   :tag: analyzer to toggle
   

   :returns: true if the operation succeeded

.. zeek:id:: Spicy::enable_protocol_analyzer
   :source-code: builtin-plugins/Zeek_Spicy/Zeek/Spicy/bare.zeek 63 66

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`) : :zeek:type:`bool`

   Enable a specific Spicy protocol analyzer if not already active. If this
   analyzer replaces an standard analyzer, that one will automatically be
   disabled.
   

   :tag: analyzer to toggle
   

   :returns: true if the operation succeeded


