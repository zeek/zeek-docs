:tocdepth: 3

zeexygen/example.zeek
=====================
.. zeek:namespace:: ZeexygenExample

This is an example script that demonstrates Zeexygen-style
documentation.  It generally will make most sense when viewing
the script's raw source code and comparing to the HTML-rendered
version.

Comments in the from ``##!`` are meant to summarize the script's
purpose.  They are transferred directly in to the generated
`reStructuredText <http://docutils.sourceforge.net/rst.html>`_
(reST) document associated with the script.

.. tip:: You can embed directives and roles within ``##``-stylized comments.

There's also a custom role to reference any identifier node in
the Zeek Sphinx domain that's good for "see alsos", e.g.

See also: :zeek:see:`ZeexygenExample::a_var`,
:zeek:see:`ZeexygenExample::ONE`, :zeek:see:`SSH::Info`

And a custom directive does the equivalent references:

.. zeek:see:: ZeexygenExample::a_var ZeexygenExample::ONE SSH::Info

:Namespace: ZeexygenExample
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/http </scripts/base/protocols/http/index>`, :doc:`policy/frameworks/software/vulnerable.zeek </scripts/policy/frameworks/software/vulnerable.zeek>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================= =======================================================
:zeek:id:`ZeexygenExample::an_option`: :zeek:type:`set` :zeek:attr:`&redef`             Add documentation for "an_option" here.
:zeek:id:`ZeexygenExample::option_with_init`: :zeek:type:`interval` :zeek:attr:`&redef` Default initialization will be generated automatically.
======================================================================================= =======================================================

State Variables
###############
========================================================================== ========================================================================
:zeek:id:`ZeexygenExample::a_var`: :zeek:type:`bool`                       Put some documentation for "a_var" here.
:zeek:id:`ZeexygenExample::summary_test`: :zeek:type:`string`              The first sentence for a particular identifier's summary text ends here.
:zeek:id:`ZeexygenExample::var_without_explicit_type`: :zeek:type:`string` Types are inferred, that information is self-documenting.
========================================================================== ========================================================================

Types
#####
==================================================================================== ===========================================================
:zeek:type:`ZeexygenExample::ComplexRecord`: :zeek:type:`record` :zeek:attr:`&redef` General documentation for a type "ComplexRecord" goes here.
:zeek:type:`ZeexygenExample::Info`: :zeek:type:`record`                              An example record to be used with a logging stream.
:zeek:type:`ZeexygenExample::SimpleEnum`: :zeek:type:`enum`                          Documentation for the "SimpleEnum" type goes here.
:zeek:type:`ZeexygenExample::SimpleRecord`: :zeek:type:`record`                      General documentation for a type "SimpleRecord" goes here.
==================================================================================== ===========================================================

Redefinitions
#############
=============================================================== ====================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                         
:zeek:type:`Notice::Type`: :zeek:type:`enum`                    
:zeek:type:`ZeexygenExample::SimpleEnum`: :zeek:type:`enum`     Document the "SimpleEnum" redef here with any special info regarding
                                                                the *redef* itself.
:zeek:type:`ZeexygenExample::SimpleRecord`: :zeek:type:`record` Document the record extension *redef* itself here.
=============================================================== ====================================================================

Events
######
======================================================== ==========================
:zeek:id:`ZeexygenExample::an_event`: :zeek:type:`event` Summarize "an_event" here.
======================================================== ==========================

Functions
#########
============================================================= =======================================
:zeek:id:`ZeexygenExample::a_function`: :zeek:type:`function` Summarize purpose of "a_function" here.
============================================================= =======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: ZeexygenExample::an_option

   :Type: :zeek:type:`set` [:zeek:type:`addr`, :zeek:type:`addr`, :zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Add documentation for "an_option" here.
   The type/attribute information is all generated automatically.

.. zeek:id:: ZeexygenExample::option_with_init

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10.0 msecs``

   Default initialization will be generated automatically.
   More docs can be added here.

State Variables
###############
.. zeek:id:: ZeexygenExample::a_var

   :Type: :zeek:type:`bool`

   Put some documentation for "a_var" here.  Any global/non-const that
   isn't a function/event/hook is classified as a "state variable"
   in the generated docs.

.. zeek:id:: ZeexygenExample::summary_test

   :Type: :zeek:type:`string`

   The first sentence for a particular identifier's summary text ends here.
   And this second sentence doesn't show in the short description provided
   by the table of all identifiers declared by this script.

.. zeek:id:: ZeexygenExample::var_without_explicit_type

   :Type: :zeek:type:`string`
   :Default: ``"this works"``

   Types are inferred, that information is self-documenting.

Types
#####
.. zeek:type:: ZeexygenExample::ComplexRecord

   :Type: :zeek:type:`record`

      field1: :zeek:type:`count`
         Counts something.

      field2: :zeek:type:`bool`
         Toggles something.

      field3: :zeek:type:`ZeexygenExample::SimpleRecord`
         Zeexygen automatically tracks types
         and cross-references are automatically
         inserted in to generated docs.

      msg: :zeek:type:`string` :zeek:attr:`&default` = ``"blah"`` :zeek:attr:`&optional`
         Attributes are self-documenting.
   :Attributes: :zeek:attr:`&redef`

   General documentation for a type "ComplexRecord" goes here.

.. zeek:type:: ZeexygenExample::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`

      uid: :zeek:type:`string` :zeek:attr:`&log`

      status: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

   An example record to be used with a logging stream.
   Nothing special about it.  If another script redefs this type
   to add fields, the generated documentation will show all original
   fields plus the extensions and the scripts which contributed to it
   (provided they are also @load'ed).

.. zeek:type:: ZeexygenExample::SimpleEnum

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ZeexygenExample::ONE ZeexygenExample::SimpleEnum

         Documentation for particular enum values is added like this.
         And can also span multiple lines.

      .. zeek:enum:: ZeexygenExample::TWO ZeexygenExample::SimpleEnum

         Or this style is valid to document the preceding enum value.

      .. zeek:enum:: ZeexygenExample::THREE ZeexygenExample::SimpleEnum

      .. zeek:enum:: ZeexygenExample::FOUR ZeexygenExample::SimpleEnum

         And some documentation for "FOUR".

      .. zeek:enum:: ZeexygenExample::FIVE ZeexygenExample::SimpleEnum

         Also "FIVE".

   Documentation for the "SimpleEnum" type goes here.
   It can span multiple lines.

.. zeek:type:: ZeexygenExample::SimpleRecord

   :Type: :zeek:type:`record`

      field1: :zeek:type:`count`
         Counts something.

      field2: :zeek:type:`bool`
         Toggles something.

      field_ext: :zeek:type:`string` :zeek:attr:`&optional`
         Document the extending field like this.
         Or here, like this.

   General documentation for a type "SimpleRecord" goes here.
   The way fields can be documented is similar to what's already seen
   for enums.

Events
######
.. zeek:id:: ZeexygenExample::an_event

   :Type: :zeek:type:`event` (name: :zeek:type:`string`)

   Summarize "an_event" here.
   Give more details about "an_event" here.
   
   ZeexygenExample::a_function should not be confused as a parameter
   in the generated docs, but it also doesn't generate a cross-reference
   link.  Use the see role instead: :zeek:see:`ZeexygenExample::a_function`.
   

   :name: Describe the argument here.

Functions
#########
.. zeek:id:: ZeexygenExample::a_function

   :Type: :zeek:type:`function` (tag: :zeek:type:`string`, msg: :zeek:type:`string`) : :zeek:type:`string`

   Summarize purpose of "a_function" here.
   Give more details about "a_function" here.
   Separating the documentation of the params/return values with
   empty comments is optional, but improves readability of script.
   

   :tag: Function arguments can be described
        like this.
   

   :msg: Another param.
   

   :returns: Describe the return type here.


