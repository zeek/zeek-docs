
.. _framework-input:

===============
Input Framework
===============

.. rst-class:: opening

   Zeek features a flexible input framework that allows users
   to import data into Zeek. Data is either read into Zeek tables or
   converted to events which can then be handled by scripts.
   This document gives an overview of how to use the input framework
   with some examples. For more complex scenarios it is
   worthwhile to take a look at the unit tests in
   ``testing/btest/scripts/base/frameworks/input/``.

Reading Data into Tables
========================

Probably the most interesting use-case of the input framework is to
read data into a Zeek table.

By default, the input framework reads the data in the same format
as it is written by the logging framework in Zeek - a tab-separated
ASCII file.

We will show the ways to read files into Zeek with a simple example.
For this example we assume that we want to import data from a blacklist
that contains server IP addresses as well as the timestamp and the reason
for the block.

An example input file could look like this (note that all fields must be
tab-separated):

::

        #fields ip timestamp reason
        192.168.17.1 1333252748 Malware host
        192.168.27.2 1330235733 Botnet server
        192.168.250.3 1333145108 Virus detected

To read a file into a Zeek table, two record types have to be defined.
One contains the types and names of the columns that should constitute the
table keys and the second contains the types and names of the columns that
should constitute the table values.

In our case, we want to be able to lookup IPs. Hence, our key record
only contains the server IP. All other elements should be stored as
the table content.

The two records are defined as:

.. sourcecode:: zeek

        type Idx: record {
                ip: addr;
        };

        type Val: record {
                timestamp: time;
                reason: string;
        };

Note that the names of the fields in the record definitions must correspond
to the column names listed in the '#fields' line of the log file, in this
case 'ip', 'timestamp', and 'reason'.  Also note that the ordering of the
columns does not matter, because each column is identified by name.

The log file is read into the table with a simple call of the
:zeek:id:`Input::add_table` function:

.. sourcecode:: zeek

        global blacklist: table[addr] of Val = table();

        event zeek_init() {
            Input::add_table([$source="blacklist.file", $name="blacklist",
                              $idx=Idx, $val=Val, $destination=blacklist]);
            Input::remove("blacklist");
        }

With these three lines we first create an empty table that should contain the
blacklist data and then instruct the input framework to open an input stream
named ``blacklist`` to read the data into the table. The third line removes the
input stream again, because we do not need it any more after the data has been
read.

Because some data files can - potentially - be rather big, the input framework
works asynchronously. A new thread is created for each new input stream.
This thread opens the input data file, converts the data into a Zeek format and
sends it back to the main Zeek thread.

Because of this, the data is not immediately accessible. Depending on the
size of the data source it might take from a few milliseconds up to a few
seconds until all data is present in the table. Please note that this means
that when Zeek is running without an input source or on very short captured
files, it might terminate before the data is present in the table (because
Zeek already handled all packets before the import thread finished).

Subsequent calls to an input source are queued until the previous action has
been completed. Because of this, it is, for example, possible to call
``add_table`` and ``remove`` in two subsequent lines: the ``remove`` action
will remain queued until the first read has been completed.

Once the input framework finishes reading from a data source, it fires
the :zeek:id:`Input::end_of_data` event. Once this event has been received all
data from the input file is available in the table.

.. sourcecode:: zeek

        event Input::end_of_data(name: string, source: string) {
                # now all data is in the table
                print blacklist;
        }

The table can be used while the data is still being read - it
just might not contain all lines from the input file before the event has
fired. After the table has been populated it can be used like any other Zeek
table and blacklist entries can easily be tested:

.. sourcecode:: zeek

        if ( 192.168.18.12 in blacklist )
                # take action

Sets instead of tables
----------------------

For some use cases the key/value notion that drives tabular data does
not apply, for example when the main purpose of the data is to test
for membership in a set. The input framework supports this approach by
using sets as the destination data type, and omitting ``$val`` in
:zeek:id:`Input::add_table`:

.. sourcecode:: zeek

        type Idx: record {
                ip: addr;
        };

        global blacklist: set[addr] = set();

        event zeek_init() {
                Input::add_table([$source="blacklist.file", $name="blacklist",
                                  $idx=Idx, $destination=blacklist]);
                Input::remove("blacklist");
        }


Re-reading and streaming data
-----------------------------

For many data sources, like for many blacklists, the source data is continually
changing. For these cases, the Zeek input framework supports several ways to
deal with changing data files.

The first, very basic method is an explicit refresh of an input stream. When
an input stream is open (this means it has not yet been removed by a call to
:zeek:id:`Input::remove`), the function :zeek:id:`Input::force_update` can be
called.  This will trigger a complete refresh of the table; any changed
elements from the file will be updated.  After the update is finished the
:zeek:id:`Input::end_of_data` event will be raised.

In our example the call would look like:

.. sourcecode:: zeek

        Input::force_update("blacklist");

Alternatively, the input framework can automatically refresh the table
contents when it detects a change to the input file.  To use this feature,
you need to specify a non-default read mode by setting the ``mode`` option
of the :zeek:id:`Input::add_table` call.  Valid values are ``Input::MANUAL``
(the default), ``Input::REREAD`` and ``Input::STREAM``.  For example,
setting the value of the ``mode`` option in the previous example
would look like this:

.. sourcecode:: zeek

        Input::add_table([$source="blacklist.file", $name="blacklist",
                          $idx=Idx, $val=Val, $destination=blacklist,
                          $mode=Input::REREAD]);

When using the reread mode (i.e., ``$mode=Input::REREAD``), Zeek continually
checks if the input file has been changed. If the file has been changed, it
is re-read and the data in the Zeek table is updated to reflect the current
state.  Each time a change has been detected and all the new data has been
read into the table, the ``end_of_data`` event is raised.

When using the streaming mode (i.e., ``$mode=Input::STREAM``), Zeek assumes
that the source data file is an append-only file to which new data is
continually appended. Zeek continually checks for new data at the end of
the file and will add the new data to the table.  If newer lines in the
file have the same index as previous lines, they will overwrite the
values in the output table.  Because of the nature of streaming reads
(data is continually added to the table), the ``end_of_data`` event
is never raised when using streaming reads.


Receiving change events
-----------------------

When re-reading files, it might be interesting to know exactly which lines in
the source files have changed.

For this reason, the input framework can raise an event each time when a data
item is added to, removed from, or changed in a table.

The event definition looks like this (note that you can change the name of
this event in your own Zeek script):

.. sourcecode:: zeek

        event entry(description: Input::TableDescription, tpe: Input::Event,
                    left: Idx, right: Val) {
                # do something here...
                print fmt("%s = %s", left, right);
        }

The event must be specified in ``$ev`` in the ``add_table`` call:

.. sourcecode:: zeek

        Input::add_table([$source="blacklist.file", $name="blacklist",
                          $idx=Idx, $val=Val, $destination=blacklist,
                          $mode=Input::REREAD, $ev=entry]);

The ``description`` argument of the event contains the arguments that were
originally supplied to the add_table call.  Hence, the name of the stream can,
for example, be accessed with ``description$name``. The ``tpe`` argument of the
event is an enum containing the type of the change that occurred.

If a line that was not previously present in the table has been added,
then the value of ``tpe`` will be ``Input::EVENT_NEW``. In this case ``left``
contains the index of the added table entry and ``right`` contains the
values of the added entry.

If a table entry that already was present is altered during the re-reading or
streaming read of a file, then the value of ``tpe`` will be
``Input::EVENT_CHANGED``. In
this case ``left`` contains the index of the changed table entry and ``right``
contains the values of the entry before the change. The reason for this is
that the table already has been updated when the event is raised. The current
value in the table can be ascertained by looking up the current table value.
Hence it is possible to compare the new and the old values of the table.

If a table element is removed because it was no longer present during a
re-read, then the value of ``tpe`` will be ``Input::EVENT_REMOVED``.  In this
case ``left`` contains the index and ``right`` the values of the removed
element.


Filtering data during import
----------------------------

The input framework also allows a user to filter the data during the import.
To this end, predicate functions are used. A predicate function is called
before a new element is added/changed/removed from a table. The predicate
can either accept or veto the change by returning true for an accepted
change and false for a rejected change. Furthermore, it can alter the data
before it is written to the table.

The following example filter will reject adding entries to the table when
they were generated over a month ago. It will accept all changes and all
removals of values that are already present in the table.

.. sourcecode:: zeek

        Input::add_table([$source="blacklist.file", $name="blacklist",
                          $idx=Idx, $val=Val, $destination=blacklist,
                          $mode=Input::REREAD,
                          $pred(typ: Input::Event, left: Idx, right: Val) = {
                            if ( typ != Input::EVENT_NEW ) {
                                return T;
                            }
                            return (current_time() - right$timestamp) < 30day;
                          }]);

To change elements while they are being imported, the predicate function can
manipulate ``left`` and ``right``. Note that predicate functions are called
before the change is committed to the table. Hence, when a table element is
changed (``typ`` is ``Input::EVENT_CHANGED``), ``left`` and ``right``
contain the new values, but the destination (``blacklist`` in our example)
still contains the old values. This allows predicate functions to examine
the changes between the old and the new version before deciding if they
should be allowed.


Broken input data
-----------------

The input framework notifies you of problems during data ingestion in
two ways. First, reporter messages, ending up in ``reporter.log``,
indicate the type of problem and the file in which the problem
occurred::

    #fields ts      level   message location
    0.000000        Reporter::WARNING       blacklist.file/Input::READER_ASCII: Did not find requested field ip in input data file blacklist.file.   (empty)

Second, the :zeek:type:`Input::TableDescription` and
:zeek:type:`Input::EventDescription` records feature an ``$error_ev`` member to
handle events indicating the same message and severity levels as shown
above. The use of these events mirrors that of change events.

For both approaches, the framework suppresses repeated messages
regarding the same file, so mistakes in large data files do not
trigger a message flood.

Finally, the ASCII reader allows coarse control over the robustness in
case of problems during data ingestion. Concretely, the
:zeek:id:`InputAscii::fail_on_invalid_lines` and
:zeek:id:`InputAscii::fail_on_file_problem` flags indicate whether
problems should merely trigger warnings or lead to processing failure.
Both default to warnings.


Different readers
-----------------

The input framework supports different kinds of readers for different kinds
of source data files. At the moment, the default reader reads ASCII files
formatted in the Zeek log file format (tab-separated values with a "#fields"
header line).  Several other readers are included in Zeek.

The raw reader reads a file that is
split by a specified record separator (newline by default). The contents are
returned line-by-line as strings; it can, for example, be used to read
configuration files and the like and is probably
only useful in the event mode and not for reading data to tables.

The binary reader is intended to be used with file analysis input streams (and
is the default type of reader for those streams).

The benchmark reader is being used
to optimize the speed of the input framework. It can generate arbitrary
amounts of semi-random data in all Zeek data types supported by the input
framework.

Currently, Zeek supports the following readers in addition to the 
aforementioned ones:

.. toctree::
   :maxdepth: 1

   logging-input-sqlite


Reading Data to Events
======================

The second supported mode of the input framework is reading data to Zeek
events instead of reading them to a table.

Event streams work very similarly to table streams that were already
discussed in much detail. To read the blacklist of the previous example
into an event stream, the :zeek:id:`Input::add_event` function is used.
For example:

.. sourcecode:: zeek

        type Val: record {
                ip: addr;
                timestamp: time;
                reason: string;
        };

        event blacklistentry(description: Input::EventDescription,
                             t: Input::Event, data: Val) {
                # do something here...
                print "data:", data;
        }

        event zeek_init() {
                Input::add_event([$source="blacklist.file", $name="blacklist",
                                  $fields=Val, $ev=blacklistentry]);
        }


The main difference in the declaration of the event stream is, that an event
stream needs no separate index and value declarations -- instead, all source
data types are provided in a single record definition.

Apart from this, event streams work exactly the same as table streams and
support most of the options that are also supported for table streams.

