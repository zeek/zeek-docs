:tocdepth: 3

base/protocols/smtp/files.bro
=============================
.. bro:namespace:: SMTP


:Namespace: SMTP
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/protocols/smtp/entities.bro </scripts/base/protocols/smtp/entities.bro>`, :doc:`base/protocols/smtp/main.bro </scripts/base/protocols/smtp/main.bro>`, :doc:`base/utils/conn-ids.bro </scripts/base/utils/conn-ids.bro>`

Summary
~~~~~~~
Redefinitions
#############
========================================== =
:bro:type:`SMTP::Info`: :bro:type:`record` 
========================================== =

Functions
#########
===================================================== ======================================
:bro:id:`SMTP::describe_file`: :bro:type:`function`   Default file describer for SMTP.
:bro:id:`SMTP::get_file_handle`: :bro:type:`function` Default file handle provider for SMTP.
===================================================== ======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: SMTP::describe_file

   :Type: :bro:type:`function` (f: :bro:type:`fa_file`) : :bro:type:`string`

   Default file describer for SMTP.

.. bro:id:: SMTP::get_file_handle

   :Type: :bro:type:`function` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`) : :bro:type:`string`

   Default file handle provider for SMTP.


