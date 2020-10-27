:tocdepth: 3

base/files/extract/main.zeek
============================
.. zeek:namespace:: FileExtract


:Namespace: FileExtract
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`, :doc:`base/utils/paths.zeek </scripts/base/utils/paths.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================= ================================================================
:zeek:id:`FileExtract::default_limit`: :zeek:type:`count` :zeek:attr:`&redef` The default max size for extracted files (they won't exceed this
                                                                              number of bytes).
============================================================================= ================================================================

Redefinable Options
###################
======================================================================= ========================================
:zeek:id:`FileExtract::prefix`: :zeek:type:`string` :zeek:attr:`&redef` The prefix where files are extracted to.
======================================================================= ========================================

Redefinitions
#############
========================================================================= =========================================================================================================================
:zeek:type:`Files::AnalyzerArgs`: :zeek:type:`record` :zeek:attr:`&redef` 
                                                                          
                                                                          :New Fields: :zeek:type:`Files::AnalyzerArgs`
                                                                          
                                                                            extract_filename: :zeek:type:`string` :zeek:attr:`&optional`
                                                                              The local filename to which to write an extracted file.
                                                                          
                                                                            extract_limit: :zeek:type:`count` :zeek:attr:`&default` = :zeek:see:`FileExtract::default_limit` :zeek:attr:`&optional`
                                                                              The maximum allowed file size in bytes of *extract_filename*.
:zeek:type:`Files::Info`: :zeek:type:`record` :zeek:attr:`&redef`         
                                                                          
                                                                          :New Fields: :zeek:type:`Files::Info`
                                                                          
                                                                            extracted: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                                              Local filename of extracted file.
                                                                          
                                                                            extracted_cutoff: :zeek:type:`bool` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                                              Set to true if the file being extracted was cut off
                                                                              so the whole file was not logged.
                                                                          
                                                                            extracted_size: :zeek:type:`count` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                                              The number of bytes extracted to disk.
========================================================================= =========================================================================================================================

Functions
#########
======================================================== =============================================
:zeek:id:`FileExtract::set_limit`: :zeek:type:`function` Sets the maximum allowed extracted file size.
======================================================== =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: FileExtract::default_limit

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``
   :Redefinition: from :doc:`/scripts/policy/tuning/defaults/extracted_file_limits.zeek`

      ``=``::

         104857600


   The default max size for extracted files (they won't exceed this
   number of bytes). A value of zero means unlimited.

Redefinable Options
###################
.. zeek:id:: FileExtract::prefix

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"./extract_files/"``

   The prefix where files are extracted to.

Functions
#########
.. zeek:id:: FileExtract::set_limit

   :Type: :zeek:type:`function` (f: :zeek:type:`fa_file`, args: :zeek:type:`Files::AnalyzerArgs`, n: :zeek:type:`count`) : :zeek:type:`bool`

   Sets the maximum allowed extracted file size.
   

   :f: A file that's being extracted.
   

   :args: Arguments that identify a file extraction analyzer.
   

   :n: Allowed number of bytes to be extracted.
   

   :returns: false if a file extraction analyzer wasn't active for
            the file, else true.


