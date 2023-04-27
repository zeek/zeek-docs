Directives
==========

The Zeek scripting language supports a number of directives that can
affect which scripts will be loaded or which lines in a script will be
executed.  Directives are evaluated before script execution begins.


.. zeek:keyword:: @DIR

@DIR
----

Expands to the directory pathname where the current script is located.

Example:

.. code-block:: zeek

    print "Directory:", @DIR;


.. zeek:keyword:: @FILENAME

@FILENAME
---------

Expands to the filename of the current script.

Example:

.. code-block:: zeek

    print "File:", @FILENAME;


.. zeek:keyword:: @deprecated

@deprecated
-----------

Marks the current script as deprecated. This can be placed anywhere in
the script, but a good convention is to put it as the first line.
You can also supply additional comments.

Example:

.. code-block:: zeek

    @deprecated "Use '@load foo' instead"


.. zeek:keyword:: @load

@load
-----

Loads the specified Zeek script, specified as the relative pathname
of the file (relative to one of the directories in Zeek's file search path).
If the Zeek script filename ends with ``.zeek``, then you don't need to
specify the file extension.  The filename cannot contain any whitespace.

In this example, Zeek will try to load a script
``policy/misc/capture-loss.zeek`` by looking in each directory in the file
search path (the file search path can be changed by setting the ``ZEEKPATH``
environment variable):

.. code-block:: zeek

    @load policy/misc/capture-loss

If you specify the name of a directory instead of a filename, then
Zeek will try to load a file in that directory called ``__load__.zeek``
(presumably that file will contain additional ``@load`` directives).

In this example, Zeek will try to load a file ``tuning/defaults/__load__.zeek``
by looking in each directory in the file search path:

.. code-block:: zeek

    @load tuning/defaults

The purpose of this directive is to ensure that all script dependencies
are satisfied, and to avoid having to list every needed Zeek script
on the command-line.  Zeek keeps track of which scripts have been
loaded, so it is not an error to load a script more than once (once
a script has been loaded, any subsequent ``load`` directives
for that script are ignored).


.. zeek:keyword:: @load-plugin

@load-plugin
------------

Activate a dynamic plugin with the specified plugin name.  The specified
plugin must be located in Zeek's plugin search path.  Example:

.. code-block:: zeek

    @load-plugin Demo::Rot13

By default, Zeek will automatically activate all dynamic plugins found
in the plugin search path (the search path can be changed by setting
the environment variable ``ZEEK_PLUGIN_PATH`` to a colon-separated list of
directories). However, in bare mode (``zeek -b`` dynamic plugins can be
activated only by using ``load-plugin`` or by specifying the full
plugin name on the Zeek command-line (e.g., ``zeek Demo::Rot13`` or by
setting the environment variable ``ZEEK_PLUGIN_ACTIVATE`` to a
comma-separated list of plugin names.


.. zeek:keyword:: @load-sigs

@load-sigs
----------

This works similarly to ``load`` except that in this case the filename
represents a signature file (not a Zeek script).  If the signature filename
ends with ``sig`` then you don't need to specify the file extension
in the ``load-sigs`` directive.  The filename cannot contain any
whitespace.

In this example, Zeek will try to load a signature file
``base/protocols/ssl/dpd.sig``

.. code-block:: zeek

    @load-sigs base/protocols/ssl/dpd

The format for a signature file is explained in the documentation for the
:doc:`Signature Framework </frameworks/signatures>`.


.. zeek:keyword:: @unload

@unload
-------

This specifies a Zeek script that we don't want to load (so a subsequent
attempt to load the specified script will be skipped).  However,
if the specified script has already been loaded, then this directive
has no affect.

In the following example, if the ``policy/misc/capture-loss.zeek`` script
has not been loaded yet, then Zeek will not load it:

.. code-block:: zeek

    @unload policy/misc/capture-loss


.. zeek:keyword:: @prefixes

@prefixes
---------

Specifies a filename prefix to use when looking for script files
to load automatically.  The prefix cannot contain any whitespace.

In the following example, the prefix ``cluster`` is used and all prefixes
that were previously specified are not used:

.. code-block:: zeek

    @prefixes = cluster

In the following example, the prefix ``cluster-manager`` is used in
addition to any previously-specified prefixes:

.. code-block:: zeek

    @prefixes += cluster-manager

The way this works is that after Zeek parses all script files, then for each
loaded script Zeek will take the absolute path of the script and then
it removes the portion of the directory path that is in Zeek's file
search path.  Then it replaces each ``/`` character with a period ``.``
and then prepends the prefix (specified in the ``@prefixes`` directive)
followed by a period.  The resulting filename is searched for in each
directory in Zeek's file search path.  If a matching file is found, then
the file is automatically loaded.

For example, if a script called ``local.zeek`` has been loaded, and a prefix
of ``test`` was specified, then Zeek will look for a file named
``test.local.zeek`` in each directory of Zeek's file search path.

An alternative way to specify prefixes is to use the ``-p`` Zeek
command-line option.


.. zeek:keyword:: @if

@if
---

The specified expression must evaluate to type :zeek:type:`bool`.  If the
value is true, then the following script lines (up to the next ``@else``
or ``@endif``) are available to be executed.

Example:

.. code-block:: zeek

    @if ( ver == 2 )
        print "version 2 detected";
    @endif


.. zeek:keyword:: @ifdef

@ifdef
------

This works like ``@if``, except that the result is true if the specified
identifier is defined.

Example:

.. code-block:: zeek

    @ifdef ( pi )
        print "pi is defined";
    @endif


.. zeek:keyword:: @ifndef

@ifndef
-------

This works exactly like ``@ifdef``, except that the result is true if the
specified identifier is not defined.

Example:

.. code-block:: zeek

    @ifndef ( pi )
        print "pi is not defined";
    @endif


.. zeek:keyword:: @activate-if

@activate-if
------------

A special form of ``@if`` that behaves the same if the condition is true.
If the condition is false, however, rather than blindly skipping the input, the
code will still be fully parsed (generating errors as appropriate), but it
will not be *activated*, meaning changes it makes via ``redef`` or by defining
function/hook/event handler bodies do not actually take effect.

Example:

.. code-block:: zeek

    @activate-if ( running_a_cluster() )
        event zeek_init()
            {
	    do_my_cluster_setup_stuff();
            }
    @endif

will install a ``zeek_init`` event handler *if*, at scripting load time,
``running_a_cluster()`` returns ``T``, and won't install it otherwise.

The following:

.. code-block:: zeek

    @activate-if ( running_a_cluster() )
        event zeek_init()
            {
	    oops syntax error
            }
    @endif

will *always* generate a syntax error, regardless of what
``running_a_cluster()`` returns, whereas if you used an ``@if`` then it
would only generate a syntax error if the return value was ``T``.

To ensure consistency, an ``@activate-if`` must not appear inside a
function body, and cannot ``redef`` a ``record`` or ``enum`` type.  Zeek will
also generate a warning if you nest an ``@activate-if`` inside an ``@if`` or
vice-versa.

Along with providing error-checking for your not-currently-active conditional
code, ``@activate-if`` enables better scripting code coverage assessments,
and enables more extensive *script compilation* (currently an experimental
feature), so you should prefer its use to ``@if`` when appropriate.

.. zeek:keyword:: @else

@else
-----

This directive is optional after an ``@if``, ``@ifdef``, ``@ifndef``, or
``@activate-if``.  If present, it provides an else clause.

Example:

.. code-block:: zeek

    @ifdef ( pi )
        print "pi is defined";
    @else
        print "pi is not defined";
    @endif


.. zeek:keyword:: @endif

@endif
------

This directive is required to terminate each ``@if``, ``@ifdef``,
``@ifndef``, or ``@activate-if``.


.. zeek:keyword:: @DEBUG

@DEBUG
------

This directive is not meant to be used directly from user scripts.  Internally,
it's used by interactive-debugger features (``zeek -d``) that allow arbitrary
expressions to be parsed and evaluated on their own rather than incorporated
into the usual Zeek syntax-tree formed from parsing script files.
