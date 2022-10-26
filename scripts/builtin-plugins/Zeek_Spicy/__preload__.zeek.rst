:tocdepth: 3

builtin-plugins/Zeek_Spicy/__preload__.zeek
===========================================
.. zeek:namespace:: Spicy


:Namespace: Spicy

Summary
~~~~~~~
Redefinable Options
###################
============================================================================ ======================================================================================
:zeek:id:`Spicy::abort_on_exceptions`: :zeek:type:`bool` :zeek:attr:`&redef` abort() instead of throwing HILTI # exceptions.
:zeek:id:`Spicy::codegen_debug`: :zeek:type:`string` :zeek:attr:`&redef`     Activate compile-time debugging output for given debug streams (comma-separated list).
:zeek:id:`Spicy::debug`: :zeek:type:`bool` :zeek:attr:`&redef`               Enable debug mode for code generation.
:zeek:id:`Spicy::debug_addl`: :zeek:type:`string` :zeek:attr:`&redef`        If debug is true, add selected additional instrumentation (comma-separated list).
:zeek:id:`Spicy::dump_code`: :zeek:type:`bool` :zeek:attr:`&redef`           Save all generated code into files on disk.
:zeek:id:`Spicy::enable_print`: :zeek:type:`bool` :zeek:attr:`&redef`        Show output of Spicy print statements.
:zeek:id:`Spicy::max_file_depth`: :zeek:type:`count` :zeek:attr:`&redef`     Maximum depth of recursive file analysis (Spicy analyzers only)
:zeek:id:`Spicy::optimize`: :zeek:type:`bool` :zeek:attr:`&redef`            Enable optimization for code generation.
:zeek:id:`Spicy::report_times`: :zeek:type:`bool` :zeek:attr:`&redef`        Report a break-down of compiler's execution time.
:zeek:id:`Spicy::show_backtraces`: :zeek:type:`bool` :zeek:attr:`&redef`     Include backtraces when reporting unhandled exceptions.
:zeek:id:`Spicy::skip_validation`: :zeek:type:`bool` :zeek:attr:`&redef`     Disable code validation.
============================================================================ ======================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: Spicy::abort_on_exceptions
   :source-code: builtin-plugins/Zeek_Spicy/__preload__.zeek 32 32

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   abort() instead of throwing HILTI # exceptions.

.. zeek:id:: Spicy::codegen_debug
   :source-code: builtin-plugins/Zeek_Spicy/__preload__.zeek 8 8

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Activate compile-time debugging output for given debug streams (comma-separated list).

.. zeek:id:: Spicy::debug
   :source-code: builtin-plugins/Zeek_Spicy/__preload__.zeek 11 11

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Enable debug mode for code generation.

.. zeek:id:: Spicy::debug_addl
   :source-code: builtin-plugins/Zeek_Spicy/__preload__.zeek 14 14

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   If debug is true, add selected additional instrumentation (comma-separated list).

.. zeek:id:: Spicy::dump_code
   :source-code: builtin-plugins/Zeek_Spicy/__preload__.zeek 17 17

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Save all generated code into files on disk.

.. zeek:id:: Spicy::enable_print
   :source-code: builtin-plugins/Zeek_Spicy/__preload__.zeek 29 29

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Show output of Spicy print statements.

.. zeek:id:: Spicy::max_file_depth
   :source-code: builtin-plugins/Zeek_Spicy/__preload__.zeek 38 38

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``5``

   Maximum depth of recursive file analysis (Spicy analyzers only)

.. zeek:id:: Spicy::optimize
   :source-code: builtin-plugins/Zeek_Spicy/__preload__.zeek 20 20

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Enable optimization for code generation.

.. zeek:id:: Spicy::report_times
   :source-code: builtin-plugins/Zeek_Spicy/__preload__.zeek 23 23

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Report a break-down of compiler's execution time.

.. zeek:id:: Spicy::show_backtraces
   :source-code: builtin-plugins/Zeek_Spicy/__preload__.zeek 35 35

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Include backtraces when reporting unhandled exceptions.

.. zeek:id:: Spicy::skip_validation
   :source-code: builtin-plugins/Zeek_Spicy/__preload__.zeek 26 26

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Disable code validation.


