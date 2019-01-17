:orphan:

Package: base/frameworks/analyzer
=================================

The analyzer framework allows to dynamically enable or disable Bro's
protocol analyzers, as well as to manage the well-known ports which
automatically activate a particular analyzer for new connections.

:doc:`/scripts/base/frameworks/analyzer/__load__.bro`


:doc:`/scripts/base/frameworks/analyzer/main.bro`

   Framework for managing Bro's protocol analyzers.
   
   The analyzer framework allows to dynamically enable or disable analyzers, as
   well as to manage the well-known ports which automatically activate a
   particular analyzer for new connections.
   
   Protocol analyzers are identified by unique tags of type
   :bro:type:`Analyzer::Tag`, such as :bro:enum:`Analyzer::ANALYZER_HTTP`.
   These tags are defined internally by
   the analyzers themselves, and documented in their analyzer-specific
   description along with the events that they generate.

