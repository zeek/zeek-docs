Attributes
==========

The Zeek scripting language supports the following attributes.

.. list-table::
  :header-rows: 1

  * - Name
    - Description

  * - :zeek:attr:`&redef`
    - Redefine a global constant or extend a type.

  * - :zeek:attr:`&priority`
    - Specify priority for event handler or hook.

  * - :zeek:attr:`&log`
    - Mark a record field as to be written to a log.

  * - :zeek:attr:`&optional`
    - Allow a record field value to be missing.

  * - :zeek:attr:`&default`
    - Specify a default value.

  * - :zeek:attr:`&add_func`
    - Specify a function to call for each ``redef +=``.

  * - :zeek:attr:`&delete_func`
    - Same as ``&add_func``, except for ``redef -=``.

  * - :zeek:attr:`&expire_func`
    - Specify a function to call when container element expires.

  * - :zeek:attr:`&read_expire`
    - Specify a read timeout interval.

  * - :zeek:attr:`&write_expire`
    - Specify a write timeout interval.

  * - :zeek:attr:`&create_expire`
    - Specify a creation timeout interval.

  * - :zeek:attr:`&on_change`
    - Specify a function to call on set/table changes

  * - :zeek:attr:`&raw_output`
    - Open file in raw mode (chars. are not escaped).

  * - :zeek:attr:`&error_handler`
    - Used internally for reporter framework events.

  * - :zeek:attr:`&type_column`
    - Used by input framework for :zeek:type:`port` type.

  * - :zeek:attr:`&backend`
    - Used for table persistence/synchronization.

  * - :zeek:attr:`&broker_store`
    - Used for table persistence/synchronization.

  * - :zeek:attr:`&broker_allow_complex_type`
    - Used for table persistence/synchronization.

  * - :zeek:attr:`&deprecated`
    - Marks an identifier as deprecated.

  * - :zeek:attr:`&is_assigned`
    - Suppress "used before defined" warnings from ``zeek -u`` analysis.

  * - :zeek:attr:`&is_used`
    - Suppress "unused assignment" warnings from ``zeek -u`` analysis.

.. _attribute-propagation-pitfalls:

.. warning::

    A confusing pitfall can be mistaking that attributes bind to a *variable*
    or a *type*, where in reality they bind to a *value*.  Example:

    .. code-block:: zeek

        global my_table: table[count] of string &create_expire=1sec;

        event zeek_init()
            {
            my_table = table();
            my_table[1] = "foo";
            }

    In the above, the re-assignment of ``my_table`` will also drop the original
    *value*'s :zeek:attr:`&create_expire` and no entries will ever be expired
    from ``my_table``.  The alternate way of re-assignment that creates a new
    table *value* with the expected attribute would be:

    .. code-block:: zeek

        my_table = table() &create_expire=1sec;

Here is a more detailed explanation of each attribute:


.. zeek:attr:: &redef

&redef
------

Allows use of a :zeek:keyword:`redef` to redefine initial values of
global variables (i.e., variables declared either :zeek:keyword:`global`
or :zeek:keyword:`const`).  Example:

.. code-block:: zeek

    const clever = T &redef;
    global cache_size = 256 &redef;

Note that a variable declared ``global`` can also have its value changed
with assignment statements (doesn't matter if it has the :zeek:attr:`&redef`
attribute or not).


.. zeek:attr:: &priority

&priority
---------

Specifies the execution priority (as a signed integer) of a hook or
event handler. Higher values are executed before lower ones. The
default value is ``0``.  Example:

.. code-block:: zeek

    event zeek_init() &priority=10
        {
        print "high priority";
        }


.. zeek:attr:: &log

&log
----

Writes a :zeek:type:`record` field to the associated log stream.


.. zeek:attr:: &optional

&optional
---------

Allows a record field value to be missing (i.e., neither initialized nor
ever assigned a value).

In this example, the record could be instantiated with either
``myrec($a=127.0.0.1)`` or ``myrec($a=127.0.0.1, $b=80/tcp)``:

.. code-block:: zeek

    type myrec: record { a: addr; b: port &optional; };

The ``?$`` operator can be used to check if a record field has a value or
not (it returns a ``bool`` value of ``T`` if the field has a value,
and ``F`` if not).


.. zeek:attr:: &default

&default
--------

Specifies a default value for a record field, container element, or a
function/hook/event parameter.

In this example, the record could be instantiated with either
``myrec($a=5, $c=3.14)`` or ``myrec($a=5, $b=53/udp, $c=3.14)``:

.. code-block:: zeek

    type myrec: record { a: count; b: port &default=80/tcp; c: double; };

In this example, the table will return the string ``"foo"`` for any
attempted access to a non-existing index:

.. code-block:: zeek

    global mytable: table[count] of string &default="foo";

When used with function/hook/event parameters, all of the parameters
with the :zeek:attr:`&default` attribute must come after all other parameters.
For example, the following function could be called either as ``myfunc(5)``
or as ``myfunc(5, 53/udp)``:

.. code-block:: zeek

    function myfunc(a: count, b: port &default=80/tcp)
        {
        print a, b;
        }


.. zeek:attr:: &add_func

&add_func
---------

Can be applied to an identifier with &redef to specify a function to
be called any time a ``redef <id> += ...`` declaration is parsed.  The
function takes two arguments of the same type as the identifier, the first
being the old value of the variable and the second being the new
value given after the ``+=`` operator in the :zeek:keyword:`redef` declaration.  The
return value of the function will be the actual new value of the
variable after the "redef" declaration is parsed.


.. zeek:attr:: &delete_func

&delete_func
------------

Same as :zeek:attr:`&add_func`, except for :zeek:keyword:`redef` declarations
that use the ``-=`` operator.


.. zeek:attr:: &expire_func

&expire_func
------------

Called right before a container element expires. The function's first
argument is of the same type as the container it is associated with.
The function then takes a variable number of arguments equal to the
number of indexes in the container. For example, for a
``table[string,string] of count`` the expire function signature is:

.. code-block:: zeek

    function(t: table[string, string] of count, s: string, s2: string): interval

The return value is an :zeek:type:`interval` indicating the amount of
additional time to wait before expiring the container element at the
given index (which will trigger another execution of this function).


.. zeek:attr:: &read_expire

&read_expire
------------

Specifies a read expiration timeout for container elements. That is,
the element expires after the given amount of time since the last
time it has been read. Note that a write also counts as a read.


.. zeek:attr:: &write_expire

&write_expire
-------------

Specifies a write expiration timeout for container elements. That
is, the element expires after the given amount of time since the
last time it has been written.


.. zeek:attr:: &create_expire

&create_expire
--------------

Specifies a creation expiration timeout for container elements. That
is, the element expires after the given amount of time since it has
been inserted into the container, regardless of any reads or writes.


.. zeek:attr:: &on_change

&on_change
----------

Called right after a change has been applied to a container. The function's
first argument is of the same type as the container it is associated with,
followed by a :zeek:see:`TableChange` record which specifies the type of change
that happened. The function then takes a variable number of arguments equal to
the number of indexes in the container, followed by an argument for the value
of the container (if the container has a value) For example, for a
``table[string,string] of count`` the ``&on_change`` function signature is:

.. code-block:: zeek

    function(t: table[string, string] of count, tpe: TableChange,
             s: string, s2: string, val: count)

For a ``set[count]`` the function signature is:

.. code-block:: zeek

    function(s: set[count], tpe: TableChange, c: count)

The passed value specifies the state of a value before the change, where this
makes sense. In case a element is changed, removed, or expired, the passed
value will be the value before the change, removal, or expiration. When an
element is added, the passed value will be the value of the added element
(since no old element existed).

Note that the ``&on_change`` function is only called when the container itself
is modified (due to an assignment, delete operation, or expiry). When a
container contains a complex element (like a record, set, or vector), changes
to these complex elements are not propagated back to the parent.  For example,
in this example the ``change_function`` for the table will only be called once,
when ``s`` is inserted,  but it will not be called when ``s`` is changed:

.. code-block:: zeek

    local t: table[string] of set[string] &on_change=change_function;
    local s: set[string] = set();
    t["s"] = s; # change_function of t is called
    add s["a"]; # change_function of t is _not_ called.

Also note that the ``&on_change`` function of a container will not be called
when the container is already executing its ``&on_change`` function. Thus,
writing an ``&on_change`` function like this is supported and will not lead to
a infinite loop:

.. code-block:: zeek

    local t: table[string] of set[string] &on_change=change_function;

    function change_function(t: table[string, int] of count, tpe: TableChange,
                             idxa: string, idxb: int, val: count)
        {
        t[idxa, idxb] = val+1;
        }


.. zeek:attr:: &raw_output

&raw_output
-----------

Opens a file in raw mode, i.e., non-ASCII characters are not escaped.


.. zeek:attr:: &error_handler

&error_handler
--------------

Internally set on the events that are associated with the reporter
framework: :zeek:id:`reporter_info`, :zeek:id:`reporter_warning`, and
:zeek:id:`reporter_error`.  It prevents any handlers of those events
from being able to generate reporter messages that go through any of
those events (i.e., it prevents an infinite event recursion).  Instead,
such nested reporter messages are output to stderr.


.. zeek:attr:: &type_column

&type_column
------------

Used by the input framework. It can be used on columns of type
:zeek:type:`port` (such a column only contains the port number) and
specifies the name of an additional column in
the input file which specifies the protocol of the port (tcp/udp/icmp).

In the following example, the input file would contain four columns
named ``ip``, ``srcp``, ``proto``, and ``msg``:

.. code-block:: zeek

    type Idx: record {
        ip: addr;
    };


    type Val: record {
        srcp: port &type_column = "proto";
        msg: string;
    };


.. zeek:attr:: &backend

&backend
--------

Used for persisting tables/sets and/or synchronizing them over a cluster.

This attribute binds a table to a Broker store. Changes to the table
are sent to the Broker store, and changes to the Broker store are applied
back to the table.

Since Broker stores are synchronized over a cluster, this sends
table changes to all other nodes in the cluster. When using a persistent Broker
store backend, the content of the tables/sets will be restored on startup.

This attribute expects the type of backend you want to use for the table. For
example, to bind a table to a memory-backed Broker store, use:

.. code-block:: zeek

    global t: table[string] of count &backend=Broker::MEMORY;

.. zeek:attr:: &broker_store

&broker_store
-------------

This attribute is similar to :zeek:attr:`&backend` in allowing a zeek table to 
bind to a Broker store. It differs from :zeek:attr:`&backend` as this attribute
allows you to specify the Broker store you want to bind, without creating it.

Use this if you want to bind a table to a Broker store with special options.

Example:

.. code-block:: zeek

     global teststore: opaque of Broker::Store;

     global t: table[string] of count &broker_store="teststore";

     event zeek_init()
         {
         teststore = Broker::create_master("teststore");
         }

.. zeek:attr:: &broker_allow_complex_type

&broker_allow_complex_type
--------------------------

By default only tables containing atomic types can be bound to Broker stores.
Specifying this attribute before :zeek:attr:`&backend` or :zeek:attr:`&broker_store`
disables this safety feature and allows complex types to be stored in a Broker backed
table.

.. warning::

    Storing complex types in Broker backed store comes with severe restrictions.
    When you modify a stored complex type after inserting it into a table, that change in a stored complex type 
    will *not propagate* to Broker. Hence to send out the new value, so that it will be persisted/synchronized
    over the cluster, you will have to re-insert the complex type into the local zeek table.

    For example:

    .. code-block:: zeek

            type testrec: record {
                a: count;
            };

            global t: table[string] of testrec &broker_allow_complex_type &backend=Broker::MEMORY;

            event zeek_init()
                {
                local rec = testrec($a=5);
                t["test"] = rec;
                rec$a = 6; # This will not propagate to Broker! You have to re-insert.
                # Propagate new value to Broker:
                t["test"] = rec;
                }

.. zeek:attr:: &deprecated

&deprecated
-----------

The associated identifier is marked as deprecated and will be
removed in a future version of Zeek.  Look in the :file:`NEWS` file for more
instructions to migrate code that uses deprecated functionality.
This attribute can be assigned an optional string literal value to
print along with the deprecation warning. The preferred format of
this warning message should include the version number in which
the identifier will be removed:

.. code-block:: zeek

    type warned: string &deprecated="Remove in vX.Y.  This type is deprecated because of reasons, use 'foo' instead.";

.. zeek:attr:: &is_assigned

&is_assigned
------------

Zeek has static analysis capabilities
for detecting locations in a script that attempt to use a
local variable before it is necessarily defined/assigned.  You activate
this using the ``-u`` command-line flag.

However the static analysis lacks sufficient power to tell that some
values are being used safely (guaranteed to have been assigned).  In order to
enable users to employ ``-u`` on their own scripts without being
distracted by these false positives, the ``&is_assigned`` attribute can be
associated with a variable to inform Zeek's analysis that the
script writer asserts the value will be set, suppressing the associated
warnings.

.. code-block:: zeek
  :caption: test1.zeek
  :linenos:

    event zeek_init()
        {
        local a: count;
        print a;
        }

.. code-block:: console

  $ zeek -b -u test1.zeek

::

  warning in ./test1.zeek, line 4: possibly used without definition (a)
  expression error in ./test1.zeek, line 4: value used but not set (a)

.. code-block:: zeek
  :caption: test2.zeek
  :linenos:

    event zeek_init()
        {
        # Note this is not a real place to want to use &is_assigned since it's
        # clearly a bug, but it demonstrates suppression of warning.
        local a: count &is_assigned;
        print a;
        }

.. code-block:: console

  $ zeek -b -u test2.zeek

::

  expression error in ./test2.zeek, line 6: value used but not set (a)

.. zeek:attr:: &is_used

&is_used
--------

Zeek has static analysis capabilities
for detecting locations in a script where local variables are assigned
values that are not subsequently used (i.e. "dead code").
For cases where it's desirable
to suppress the warning, the ``&is_used`` attribute may be applied, for
example:

.. code-block:: zeek
  :caption: test.zeek
  :linenos:

    event zeek_init()
        {
        local please_warn: string = "test";
        local please_no_warning: string = "test" &is_used;
        }

.. code-block:: console

  $ zeek -a -b -u test.zeek

::

  warning: please_warn assignment unused: please_warn = test; ./test.zeek, line 3
