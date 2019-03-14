
This document summarizes the most important changes in the current Bro
release. For an exhaustive list of changes, see the ``CHANGES`` file
(note that submodules, such as Broker, come with their own ``CHANGES``.)

Bro 2.7
=======

New Functionality
-----------------

- Added support for DNSSEC resource records RRSIG, DNSKEY, DS, NSEC, and NSEC3.
  The associated events are:

  - dns_RRSIG
  - dns_DNSKEY
  - dns_DS
  - dns_NSEC
  - dns_NSEC3

- Bro's Plugin framework now allows a patch version.  If a patch version is not
  provided, it will default to 0.  To specify this, modify the plugin
  Configuration class in your ``src/Plugin.cc`` and set
  ``config.version.patch``.  Note that the default plugin skeleton
  includes a unit test whose Baseline has the plugin version number in
  it and that will now fail due to the version number now including a
  patch number.  For those that want to keep the unit test, simply adapt
  the unit test/baseline to include the new plugin patch number.

- The default http.log not includes a field for the HTTP request Origin header.

- Support for decapsulating VXLAN tunnels.

Changed Functionality
---------------------

- The for-loop index variable for vectors has been changed from
  'int' to 'count' type.  It's unlikely this would alter/break any
  script behavior unless they were explicitly inspecting the variable's
  type (and there's typically no reason to do that).

- The startup/initialization behavior has changed such that any errors
  encountered while processing the ``bro_init()`` event will cause the
  process to terminate rather than continue on the main run loop.

- The ``dns_state`` field within ``connection`` records has changed: the
  ``pending_queries`` and ``pending_replies`` fields are now ``&optional``,
  and there is a new field ``pending_query`` that is populated before
  ``pending_queries``.  If you have scripts that access the ``pending_queries``
  or ``pending_replies`` fields, they will need to be updated.
  This change was made to improve performance.

- The ternary operator ("<expr> ? <alt1> : <alt2>") now enforces that
  if "<alt1>" and "<alt2>" are both records, they are of the same
  type. It was always assumed that they were, but code might have
  still worked even if not.

- The "orig_fuids", "orig_filenames", "orig_mime_types" http.log fields
  as well as their "resp" counterparts are now limited to having
  "HTTP::max_files_orig" or "HTTP::max_files_resp" entries, which are 15
  by default.  The limit can also be ignored case-by-case via the
  "HTTP::max_files_policy" hook.

Removed Functionality
---------------------

Deprecated Functionality
------------------------

Bro 2.6
=======

New Functionality
-----------------

- Bro has switched to using the new Broker library for all its
  communication. Broker's API has been completely redesigned (compared
  to the version in 2.5), and much of its implementation has been
  redone. There's a new script-level "broker" framework that
  supersedes the old "communication" framework, which is now
  deprecated.  All scripts that ship with Bro have been ported to use
  Broker.  BroControl has likewise been ported to use Broker.

  For more about the new Broker framework, see
  https://www.bro.org/sphinx-git/frameworks/broker.html.  There's also
  a guide there for porting existing Bro scripts to Broker. For more
  about Broker itself, including its API for external applications,
  see https://bro-broker.readthedocs.io/en/stable

  When using BroControl, the function of proxies has changed with
  Broker. If you are upgrading and have configured more than one proxy
  currenty, we recommend going back down to a single proxy node now.
  That should be fine unless you are using custom scripts doing
  significant data distribution through the new cluster framework.

  A side effect of the switch to using Broker is that each Bro node now runs
  as a single process instead of two.  Also, the number of file descriptors
  being polled in Bro's main event loop has been reduced (1 per worker
  versus 5).  This should increase the number of workers one can
  use before reaching the common 1024 file descriptor limitation of
  "select()".

- Bro now has new "is" and "as" script operators for dynamic
  type-checking and casting.

    - "v as T" casts a value v into a value of type T, assuming that's
      possible (if not, it triggers a runtime error).

    - "v is T" returns a boolean indicating whether value v can be
      casted into type T (i.e., if true then "v as T" will succeed).

    This casting supports three cases currently: (1) a value of
    declared type "any" can be casted to its actual underlying type;
    (2) Broker values can be casted to their corresponding script
    types; and (3) all values can be casted to their declared types
    (i.e., a no-op).

    Example for "any"::

        # cat a.bro
        function check(a: any)
            {
            local s: string = "default";

            if ( a is string )
                s = (a as string);

            print fmt("s=%s", s);
            }

        event bro_init()
            {
            check("Foo");
            check(1);
            }

        # bro a.bro
        s=Foo
        s=default

- The existing "switch" statement got extended to now also support switching by
  type rather than value. The new syntax supports two type-based versions
  of "case":

    - "case type T: ...": Take branch if operand can be casted to type T.

    - "case type T as x: ... ": Take branch if operand can be casted
      to type T, and make the casted value available through ID "x".

    Multiple types can be listed per branch, separated by commas.
    However, one cannot mix cases with expressions and types inside a
    single switch statement.

    Example::

        function switch_one(v: any)
            {
            switch (v) {
            case type string:
                    print "It's a string!";
                    break;

            case type count as c:
                    print "It's a count!", c;
                    break;

            case type bool, type addr:
                    print "It's a bool or address!";
                    break;

            default:
                    print "Something else!";
                    break;
            }
            }

- Bro now comes with a new "configuration framework" that allows
  updating script options dynamically at runtime. This functionality
  consists of three larger pieces working together:

  - Option variables: The new "option" keyword allows variables to be
    declared as runtime options. Such variables cannot be changed
    using normal assignments. Instead, they can be changed using the
    new function "Config::set_value".  This function will automatically
    apply the change to all nodes in a cluster.  Note that options can also
    be changed using the new function "Option::set", but this function will
    not send the change to any other nodes, so Config::set_value should
    typically be used instead of Option::set.

    Various redef-able constants in the standard Bro scripts have
    been converted to runtime options.  This change will not affect any
    user scripts because the initial value of runtime options can still be
    redefined with a "redef" declaration.  Example::

        option testvar = "old value";
        redef testvar = "new value";

    It is possible to "subscribe" to an option through
    "Option::set_change_handler", which will trigger a handler callback
    when an option changes. Change handlers can optionally modify
    values before they are applied by returning the desired value, or
    reject updates by returning the old value. Priorities can be
    specified if there are several handlers for one option.

    Example script::

        option testbool: bool = T;

        function option_changed(ID: string, new_value: bool): bool
            {
            print fmt("Value of %s changed from %s to %s", ID, testbool, new_value);
            return new_value;
            }

        event bro_init()
            {
            print "Old value", testbool;
            Option::set_change_handler("testbool", option_changed);
            Option::set("testbool", F);
            print "New value", testbool;
            }

  - Script-level configuration framework: The new script framework
    base/framework/config facilitates reading in new option values
    from external files at runtime. The format for these files looks
    like this::

        [option name][tab/spaces][new variable value]

    Configuration files to read can be specified by adding them to
    "Config::config_files".

    Usage example::

        redef Config::config_files += { "/path/to/config.dat" };

        module TestConfig;

        export {
            option testbool: bool = F;
        }

    The specified file will now be monitored continuously for changes, so
    that writing "TestConfig::testbool T" into ``/path/to/config.dat`` will
    automatically update the option's value accordingly.

    The configuration framework creates a ``config.log`` that shows all
    value changes that took place.

  - Config reader: Internally, the configuration framework uses a new
    type of input reader to read such configuration files into Bro.
    The reader uses the option name to look up the type that variable
    has, converts the read value to the correct type, and then updates
    the option's value. Example script use::

        type Idx: record {
            option_name: string;
        };

        type Val: record {
            option_val: string;
        };

        global currconfig: table[string] of string = table();

        event InputConfig::new_value(name: string, source: string, id: string, value: any)
            {
            print id, value;
            }

        event bro_init()
            {
            Input::add_table([$reader=Input::READER_CONFIG, $source="../configfile", $name="configuration", $idx=Idx, $val=Val, $destination=currconfig, $want_record=F]);
            }

- Support for OCSP and Signed Certificate Timestamp. This adds the
  following events and BIFs:

  - Events:

    - ocsp_request
    - ocsp_request_certificate
    - ocsp_response_status
    - ocsp_response_bytes
    - ocsp_response_certificate
    - ocsp_extension
    - x509_ocsp_ext_signed_certificate_timestamp
    - ssl_extension_signed_certificate_timestamp

  - Functions:

    - sct_verify
    - x509_subject_name_hash
    - x509_issuer_name_hash
    - x509_spki_hash

- The SSL scripts provide a new hook "ssl_finishing(c: connection)"
  to trigger actions after the handshake has concluded.

- New functionality has been added to the TLS parser, adding several
  events. These events mostly extract information from the server and client
  key exchange messages. The new events are:

  - ssl_ecdh_server_params
  - ssl_dh_server_params
  - ssl_server_signature
  - ssl_ecdh_client_params
  - ssl_dh_client_params
  - ssl_rsa_client_pms

  Since "ssl_ecdh_server_params" contains more information than the old
  "ssl_server_curve" event, "ssl_server_curve" is now marked as deprecated.

- The "ssl_application_data" event was retired and replaced with
  "ssl_plaintext_data".

- Some SSL events were changed and now provide additional data. These events
  are:

  - ssl_client_hello
  - ssl_server_hello
  - ssl_encrypted_data

  If you use these events, you can make your scripts work on old and new
  versions of Bro by wrapping the event definition in an "@if", for example::

    @if ( Version::at_least("2.6") || ( Version::number == 20500 && Version::info$commit >= 944 ) )
    event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
    @else
    event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec)
    @endif

- Functions for retrieving files by their ID have been added:

  - Files::file_exists
  - Files::lookup_File

- New functions in the logging API:

  - Log::get_filter_names
  - Log::enable_stream

- HTTP now recognizes and skips upgraded/websocket connections.  A new event,
  "http_connection_upgrade", is raised in such cases.

- A new hook, HTTP::sqli_policy, may be used to whitelist requests that
  could otherwise be counted as SQL injection attempts.

- Added a MOUNT3 protocol parser

  - This is not enabled by default (no ports are registered and no
    DPD signatures exist, so no connections will end up attaching the
    new Mount analyzer).  If it were to be activated by users, the
    following events are available:

    - mount_proc_null
    - mount_proc_mnt
    - mount_proc_umnt
    - mount_proc_umnt_all
    - mount_proc_not_implemented
    - mount_reply_status

- Added new NFS events:

  - nfs_proc_symlink
  - nfs_proc_link
  - nfs_proc_sattr

- The SMB scripts in ``policy/protocols/smb`` are now moved into
  ``base/protocols/smb`` and loaded/enabled by default.  If you previously
  loaded these scripts from their ``policy/`` location (in local.bro or
  other custom scripts) you may now remove/change those although they
  should still work since ``policy/protocols/smb`` is simply a placeholder
  script that redirects to the new ``base/`` location.

- Added new SMB events:

  - smb1_transaction_secondary_request
  - smb1_transaction2_secondary_request
  - smb1_transaction_response

- Bro can now decrypt Kerberos tickets, and retrieve the authentication from
  them, given a suitable keytab file.

- Added support for bitwise operations on "count" values.  '&', '|' and
  '^' are binary "and", "or" and "xor" operators, and '~' is a unary
  ones-complement operator.

- The '&' and '|' operators can apply to patterns, too.  p1 & p2 yields
  a pattern that represents matching p1 followed by p2, and p1 | p2 yields
  a pattern representing matching p1 or p2.  The p1 | p2 functionality was
  semi-present in previous versions of Bro, but required constants as
  its operands; now you can use any pattern-valued expressions.

- You can now specify that a pattern matches in a case-insensitive
  fashion by adding 'i' to the end of its specification.  So for example
  /fOO/i == "Foo" yields T, as does /fOO/i in "xFoObar".

  You can achieve the same functionality for a subpattern enclosed in
  parentheses by adding "?i:" to the open parenthesis.  So for example
  /foo|(?i:bar)/ will match "BaR", but not "FoO".

  For both ways of specifying case-insensitivity, characters enclosed in
  double quotes remain case-sensitive.  So for example /"foo"/i will not
  match "Foo", but it will match "foo".

- "make install" now installs Bro's include headers (and more) into
  "--prefix" so that compiling plugins no longer needs access to a
  source/build tree. For OS distributions, this also facilitates
  creating "bro-devel" packages providing all files necessary to build
  plugins.

- Bro now supports PPPoE over QinQ.

- Bro now supports OpenSSL 1.1.

- The new connection/conn.log history character 'W' indicates that
  the originator ('w' = responder) advertised a TCP zero window
  (instructing the peer to not send any data until receiving a
  non-zero window).

- The connection/conn.log history characters 'C' (checksum error seen),
  'T' (retransmission seen), and 'W' (zero window advertised) are now
  repeated in a logarithmic fashion upon seeing multiple instances
  of the corresponding behavior.  Thus a connection with 2 C's in its
  history means that the originator sent >= 10 packets with checksum
  errors; 3 C's means >= 100, etc.

- The above connection history behaviors occurring multiple times
  (i.e., starting at 10 instances, than again for 100 instances,
  etc.) generate corresponding events:

  - tcp_multiple_checksum_errors
  - udp_multiple_checksum_errors
  - tcp_multiple_zero_windows
  - tcp_multiple_retransmissions

  Each has the same form, e.g.::

      event tcp_multiple_retransmissions(c: connection, is_orig: bool,
				                         threshold: count);

- Added support for set union, intersection, difference, and comparison
  operations.  The corresponding operators for the first three are
  "s1 | s2", "s1 & s2", and "s1 - s2".  Relationals are in terms
  of subsets, so "s1 < s2" yields true if s1 is a proper subset of s2
  and "s1 == s2" if the two sets have exactly the same elements.
  "s1 <= s2" holds for subsets or equality, and similarly "s1 != s2",
  "s1 > s2", and "s1 >= s2" have the expected meanings in terms
  of non-equality, proper superset, and superset-or-equal.

- An expression of the form "v += e" will append the value of the expression
  "e" to the end of the vector "v" (of course assuming type-compatibility).
  "redef v += { a, b, c }" will similarly extend a vector previously declared
  with &redef by appending the result of expressions "a", "b", and "c" to
  the vector at initialization-time.

- A new "@deprecated" directive was added. It marks a script-file as
  deprecated.

Changed Functionality
---------------------

- All communication is now handled through Broker, requiring changes
  to existing scripts to port them over to the new API. The Broker
  framework documentation comes with a porting guide.

- The DHCP analyzer and its script-layer interface have been rewritten.

  - Supports more DHCP options than before.

  - The DHCP log now represents DHCP sessions based on transaction ID
    and works on Bro cluster deployments.

  - Removed the ``policy/protocols/dhcp/known-devices-and-hostnames.bro``
    script since it's generally less relevant now with the updated log.

  - Removed the ``base/protocols/dhcp/utils.bro`` script and thus the
    "reverse_ip" function.

  - Replaced all DHCP events with the single "dhcp_message" event.
    The list of removed events includes:

    - dhcp_discover
    - dhcp_offer
    - dhcp_request
    - dhcp_decline
    - dhcp_ack
    - dhcp_nak
    - dhcp_release
    - dhcp_inform

  - A new script, ``policy/protocols/dhcp/deprecated_events.bro``, may be
    loaded to aid those transitioning away from the list of "removed"
    events above.  The script provides definitions for the old events
    and automatically generates them from a "dhcp_message" handler, thus
    providing equivalent functionality to the previous Bro release.
    Such usage emits deprecation warnings.

- Removed ``policy/misc/known-devices.bro`` script and thus
  ``known_devices.log`` will no longer be created.

- The "--with-binpac" configure option has changed to mean "path
  to the binpac executable" instead of "path to binpac installation root".

- The MIME types used to identify X.509 certificates in SSL
  connections changed from "application/pkix-cert" to
  "application/x-x509-user-cert" for host certificates and
  "application/x-x509-ca-cert" for CA certificates.

- The "ssl_server_curve" event is considered deprecated and will be removed
  in the future.  See the new "ssl_ecdh_server_params" event for a
  replacement.

- The Socks analyzer no longer logs passwords by default. This
  brings its behavior in line with the FTP/HTTP analyzers which also
  do not log passwords by default.

  To restore the previous behavior and log Socks passwords, use::

      redef SOCKS::default_capture_password = T;

- The DNS base scripts no longer generate some noisy and annoying
  weirds:

  - dns_unmatched_msg
  - dns_unmatched_msg_quantity
  - dns_unmatched_reply

- The "tunnel_parents" field of ``conn.log`` is now marked ``&optional``, so,
  in the default configuration of logs, this field will show "-"
  instead of "(empty)" for connections that lack any tunneling.

- SMB event argument changes:

  - "smb1_transaction_request" now has two additional arguments, "parameters"
    and "data" strings

  - "smb1_transaction2_request" now has an additional "args" record argument

- The "SMB::write_cmd_log" option has been removed and the corresponding
  logic moving to ``policy/protocols/smb/log-cmds.bro`` which can simply
  be loaded to produce the same effect of toggling the old flag on.

- SSL event argument changes:

  - "ssl_server_signature" now has an additional argument
    "signature_and_hashalgorithm".

- The "dnp3_header_block" event no longer has the "start" parameter.

- The "string_to_pattern()" and now-deprecated "merge_pattern()"
  built-ins are no longer restricted to only be called at initialization time.

- GeoIP Legacy Database support has been replaced with GeoIP2 MaxMind DB
  format support.

  - This updates the "lookup_location" and "lookup_asn" BIFs to use
    libmaxminddb.  The motivation for this is that MaxMind is discontinuing
    GeoLite Legacy databases: no updates after April 1, 2018, no downloads
    after January 2, 2019.  It's also noted that all GeoIP Legacy databases
    may be discontinued as they are superseded by GeoIP2.

- "Weird" events are now generally suppressed/sampled by default according to
  some tunable parameters:

  - Weird::sampling_whitelist
  - Weird::sampling_threshold
  - Weird::sampling_rate
  - Weird::sampling_duration

  Those options can be changed if one needs the previous behavior of
  a "net_weird", "flow_weird", or "conn_weird" event being raised for
  every single event.

  The original ``weird.log`` may not differ much with these changes,
  except in the cases where a particular weird type exceeds the
  sampling threshold.

  Otherwise, there is a new ``weird_stats.log`` generated via
  ``policy/misc/weird-stats.bro`` which contains concise summaries
  of weird counts per type per time period.

- Improved DCE-RPC analysis via tracking of context identifier mappings

  - These DCE-RPC events now contain an additional context-id argument:

    - dce_rpc_bind
    - dce_rpc_request
    - dce_rpc_response

  - Added new events:

    - dce_rpc_alter_context
    - dce_rpc_alter_context_resp

- The default value of ``Pcap::snaplen`` changed from 8192 to 9216 bytes
  to better accommodate jumbo frames.

- Improvements to ``ntlm.log`` to fix incorrect reporting of login
  success/failure.  Also, the "status" field was removed and
  "server_nb_computer_name", "server_dns_computer_name", and
  "server_tree_name" fields added.

- BroControl: The output of the broctl "top" command has changed slightly.
  The "Proc" column has been removed from the output.  This column previously
  indicated whether each Bro process was the "parent" or "child", but this
  is no longer relevant because each Bro node now runs as a single process.

- The ``DNP3::function_codes`` name for request 0x21 has been corrected from
  "AUTHENTICATE_ERR" to "AUTHENTICATE_REQ_NR".

- The ``DNS::query_types`` names for resource records 41 and 100 have been
  corrected from "EDNS" to "OPT" and "DINFO" to "UINFO", respectively.

Removed Functionality
---------------------

- We no longer maintain any Bro plugins as part of the Bro
  distribution. Most of the plugins that used to be in aux/plugins have
  been moved over to use the Bro Package Manager instead. See
  https://packages.bro.org for a list of Bro packages currently
  available.

- The "ocsp_request" event no longer has "requestorName" parameter.

- The node-specific ``site/local-*.bro`` scripts have been removed.

- BroControl: The "IPv6Comm" and "ZoneID" options are no longer
  available (though Broker should be able to handle IPv6 automatically).

Deprecated Functionality
------------------------

- The old communication system is now deprecated and scheduled for
  removal with the next Bro release. This includes the "communication"
  framework, the ``&sychronized`` attributes, and the existing
  communication-related BiFs. Use Broker instead.

- The infrastructure for serializing Bro values into a binary
  representation is now deprecated and scheduled for removal with the
  next Bro release. This includes the ``&persistent`` attribute, as well
  as BIFs like "send_id()". Use Broker data stores and the new
  configuration framework instead.

- Mixing of scalars and vectors, such as "v + e" yielding a vector
  corresponding to the vector v with the scalar e added to each of
  its elements, has been deprecated.

- The built-in function "merge_pattern()" has been deprecated.  It will
  be replaced by the '&' operator for patterns.

- The undocumented feature of using "&&" and "||" operators for patterns
  has been deprecated.

- BroControl: The "update" command is deprecated and scheduled for
  removal with the next Bro release. Bro's new configuration framework
  is taking its place.

Bro 2.5.5
=========

Bro 2.5.5 primarily addresses security issues.

- Fix array bounds checking in BinPAC: for arrays that are fields within
  a record, the bounds check was based on a pointer to the start of the
  record rather than the start of the array field, potentially resulting
  in a buffer over-read.

- Fix SMTP command string comparisons: the number of bytes compared was
  based on the user-supplied string length and can lead to incorrect
  matches.  e.g. giving a command of "X" incorrectly matched
  "X-ANONYMOUSTLS" (and an empty commands match anything).

The following changes address potential vectors for Denial of Service
reported by Christian Titze & Jan Grashöfer of Karlsruhe Institute of
Technology:

- "Weird" events are now generally suppressed/sampled by default according
   to some tunable parameters:

  - Weird::sampling_whitelist
  - Weird::sampling_threshold
  - Weird::sampling_rate
  - Weird::sampling_duration

  Those options can be changed if one needs the previous behavior of
  a "net_weird", "flow_weird", or "conn_weird" event being raised for
  every single event.  Otherwise, there is a new weird_stats.log which
  contains concise summaries of weird counts per type per time period
  and the original weird.log may not differ much either, except in
  the cases where a particular weird type exceeds the sampling threshold.
  These changes help improve performance issues resulting from excessive
  numbers of weird events.

- Improved handling of empty lines in several text protocol analyzers
  that can cause performance issues when seen in long sequences.

- Add 'smtp_excessive_pending_cmds' weird which serves as a notification
  for when the "pending command" queue has reached an upper limit and
  been cleared to prevent one from attempting to slowly exhaust memory.

Bro 2.5.4
=========

Bro 2.5.4 primarily fixes security issues:

* Multiple fixes and improvements to BinPAC generated code related to
  array parsing, with potential impact to all Bro's BinPAC-generated
  analyzers in the form of buffer over-reads or other invalid memory
  accesses depending on whether a particular analyzer incorrectly
  assumed that the evaulated-array-length expression is actually the
  number of elements that were parsed out from the input.

* The NCP analyzer (not enabled by default and also updated to actually
  work with newer Bro APIs in the release) performed a memory allocation
  based directly on a field in the input packet and using signed integer
  storage.  This could result in a signed integer overflow and memory
  allocations of negative or very large size, leading to a crash or
  memory exhaustion.  The new NCP::max_frame_size tuning option now
  limits the maximum amount of memory that can be allocated.

There's also the following bug fixes:

* A memory leak in the SMBv1 analyzer.

* The MySQL analyzer was generally not working as intended, for example,
  it now is able to parse responses that contain multiple results/rows.

Bro 2.5.3
=========

Bro 2.5.3 fixes a security issue in Binpac generated code. In some cases
the code generated by binpac could lead to an integer overflow which can
lead to out of bound reads and allow a remote attacker to crash Bro; there
is also a possibility that this can be exploited in other ways.

Bro 2.5.2
=========

Bro 2.5.2 fixes a security issue in the ContentLine analyzer. In rare cases
a bug in the ContentLine analyzer can lead to an out of bound write of a single
byte. This allows a remote attacker to crash Bro; there also is a possibility
this can be exploited in other ways. CVE-2017-1000458 has been assigned to this
issue.

Bro 2.5.1
=========

New Functionality
-----------------

- Bro now includes bifs for rename, unlink, and rmdir.

- Bro now includes events for two extensions used by TLS 1.3:
  ssl_extension_supported_versions and ssl_extension_psk_key_exchange_modes

- Bro now includes hooks that can be used to interact with log processing
  on the C++ level.

- Bro now supports ERSPAN. Currently this ignores the ethernet header that is
  carried over the tunnel; if a MAC is logged currently only the outer MAC
  is returned.

- Added a new BroControl option CrashExpireInterval to enable
  "broctl cron" to remove crash directories that are older than the
  specified number of days (the default value is 0, which means crash
  directories never expire).

- Added a new BroControl option MailReceivingPackets to control
  whether or not "broctl cron" will mail a warning when it notices
  that no packets were seen on an interface.

- There is a new broctl command-line option "--version" which outputs
  the BroControl version.

Changed Functionality
---------------------

- The input framework's Ascii reader is now more resilient. If an input
  is marked to reread a file when it changes and the file didn't exist
  during a check Bro would stop watching the file in previous versions.
  The same could happen with bad data in a line of a file.  These
  situations do not cause Bro to stop watching input files anymore. The
  old behavior is available through settings in the Ascii reader.

- The RADIUS scripts have been reworked. Requests are now logged even if
  there is no response. The new framed_addr field in the log indicates
  if the radius server is hinting at an address for the client. The ttl
  field indicates how quickly the server is replying to the network access
  server.

- With the introduction of the Bro package manager, the Bro plugin repository
  is considered deprecated. The af_packet, postgresql, and tcprs plugins have
  already been removed and are available via bro-pkg.

Bro 2.5
=======

New Dependencies
----------------

- Bro now requires a compiler with C++11 support for building the
  source code.

- Bro now requires Python instead of Perl to compile the source code.

- When enabling Broker (which is disabled by default), Bro now requires
  version 0.14 of the C++ Actor Framework.

New Functionality
-----------------

- SMB analyzer. This is the rewrite that has been in development for
  several years. The scripts are currently not loaded by default and
  must be loaded manually by loading policy/protocols/smb. The next
  release will load the smb scripts by default.

   - Implements SMB1+2.
   - Fully integrated with the file analysis framework so that files
     transferred over SMB can be analyzed.
   - Includes GSSAPI and NTLM analyzer and reimplements the DCE-RPC
     analyzer.
   - New logs: smb_cmd.log, smb_files.log, smb_mapping.log, ntlm.log,
     and dce_rpc.log
   - Not every possible SMB command or functionality is implemented, but
     generally, file handling should work whenever files are transferred.
     Please speak up on the mailing list if there is an obvious oversight.

- Bro now includes the NetControl framework. The framework allows for easy
  interaction of Bro with hard- and software switches, firewalls, etc.
  New log files: netcontrol.log, netcontrol_catch_release.log,
  netcontrol_drop.log, and netcontrol_shunt.log.

- Bro now includes the OpenFlow framework which exposes the data structures
  necessary to interface to OpenFlow capable hardware.

- Bro's Intelligence Framework was refactored and new functionality
  has been added:

  - The framework now supports the new indicator type Intel::SUBNET.
    As subnets are matched against seen addresses, the new field 'matched'
    in intel.log was introduced to indicate which indicator type(s) caused
    the hit.

  - The new function remove() allows to delete intelligence items.

  - The intel framework now supports expiration of intelligence items.
    Expiration can be configured using the new Intel::item_expiration constant
    and can be handled by using the item_expired() hook. The new script
    do_expire.bro removes expired items.

  - The new hook extend_match() allows extending the framework. The new
    policy script whitelist.bro uses the hook to implement whitelisting.

  - Intel notices are now suppressible and mails for intel notices now
    list the identified services as well as the intel source.

- There is a new file entropy analyzer for files.

- Bro now supports the remote framebuffer protocol (RFB) that is used by
  VNC servers for remote graphical displays.  New log file: rfb.log.

- Bro now supports the Radiotap header for 802.11 frames.

- Bro now has rudimentary IMAP and XMPP analyzers examining the initial
  phases of the protocol. Right now these analyzers only identify
  STARTTLS sessions, handing them over to TLS analysis. These analyzers
  do not yet analyze any further IMAP/XMPP content.

- New funtionality has been added to the SSL/TLS analyzer:

  - Bro now supports (draft) TLS 1.3.

  - The new event ssl_extension_signature_algorithm() allows access to the
    TLS signature_algorithms extension that lists client supported signature
    and hash algorithm pairs.

  - The new event ssl_extension_key_share gives access to the supported named
    groups in TLS 1.3.

  - The new event ssl_application_data gives information about application data
    that is exchanged before encryption fully starts. This is used to detect
    when encryption starts in TLS 1.3.

- Bro now tracks VLAN IDs. To record them inside the connection log,
  load protocols/conn/vlan-logging.bro.

- A new dns_CAA_reply() event gives access to DNS Certification Authority
  Authorization replies.

- A new per-packet event raw_packet() provides access to layer 2
  information. Use with care, generating events per packet is
  expensive.

- A new built-in function, decode_base64_conn() for Base64 decoding.
  It works like decode_base64() but receives an additional connection
  argument that will be used for decoding errors into weird.log
  (instead of reporter.log).

- A new get_current_packet_header() bif returns the headers of the current
  packet.

- Three new built-in functions for handling set[subnet] and table[subnet]:

  - check_subnet(subnet, table) checks if a specific subnet is a member
    of a set/table. This is different from the "in" operator, which always
    performs a longest prefix match.

  - matching_subnets(subnet, table) returns all subnets of the set or table
    that contain the given subnet.

  - filter_subnet_table(subnet, table) works like matching_subnets, but returns
    a table containing all matching entries.

- Several built-in functions for handling IP addresses and subnets were added:

  - is_v4_subnet(subnet) checks whether a subnet specification is IPv4.

  - is_v6_subnet(subnet) checks whether a subnet specification is IPv6.

  - addr_to_subnet(addr) converts an IP address to a /32 subnet.

  - subnet_to_addr(subnet) returns the IP address part of a subnet.

  - subnet_width(subnet) returns the width of a subnet.

- The IRC analyzer now recognizes StartTLS sessions and enables the SSL
  analyzer for them.

- The misc/stats.bro script is now loaded by default and logs more Bro
  execution statistics to the stats.log file than it did previously. It
  now also uses the standard Bro log format.

- A set of new built-in functions for gathering execution statistics:

      get_net_stats(), get_conn_stats(), get_proc_stats(),
      get_event_stats(), get_reassembler_stats(), get_dns_stats(),
      get_timer_stats(), get_file_analysis_stats(), get_thread_stats(),
      get_gap_stats(), get_matcher_stats()

- Two new functions haversine_distance() and haversine_distance_ip()
  for calculating geographic distances. The latter function requires that Bro
  be built with libgeoip.

- Table expiration timeout expressions are evaluated dynamically as
  timestamps are updated.

- The pcap buffer size can be set through the new option Pcap::bufsize.

- Input framework readers stream types Table and Event can now define a custom
  event (specified by the new "error_ev" field) to receive error messages
  emitted by the input stream. This can, e.g., be used to raise notices in
  case errors occur when reading an important input source.

- The logging framework now supports user-defined record separators,
  renaming of column names, as well as extension data columns that can
  be added to specific or all logfiles (e.g., to add new names).

- The new "bro-config" script can be used to determine the Bro installation
  paths.

- New BroControl functionality in aux/broctl:

  - There is a new node type "logger" that can be specified in
    node.cfg (that file has a commented-out example).  The purpose of
    this new node type is to receive logs from all nodes in a cluster
    in order to reduce the load on the manager node.  However, if
    there is no "logger" node, then the manager node will handle
    logging as usual.

  - The post-terminate script will send email if it fails to archive
    any log files.  These mails can be turned off by changing the
    value of the new BroControl option MailArchiveLogFail.

  - Added the ability for "broctl deploy" to reload the BroControl
    configuration (both broctl.cfg and node.cfg).  This happens
    automatically if broctl detects any changes to those config files
    since the last time the config was loaded.  Note that this feature
    is relevant only when using the BroControl shell interactively.

  - The BroControl plugin API has a new function "broctl_config".
    This gives plugin authors the ability to add their own script code
    to the autogenerated broctl-config.bro script.

  - There is a new BroControl plugin for custom load balancing.  This
    plugin can be used by setting "lb_method=custom" for your worker
    nodes in node.cfg.  To support packet source plugins, it allows
    configuration of a prefix and suffix for the interface name.

- New Bro plugins in aux/plugins:

    - af_packet: Native AF_PACKET support.
    - kafka : Log writer interfacing to Kafka.
    - myricom: Native Myricom SNF v3 support.
    - pf_ring: Native PF_RING support.
    - postgresql: A PostgreSQL reader/writer.
    - redis: An experimental log writer for Redis.
    - tcprs: A TCP-level analyzer detecting retransmissions, reordering, and more.

Changed Functionality
---------------------

- Log changes:

    - Connections

        The 'history' field gains two new flags: '^' indicates that
        Bro heuristically flipped the direction of the connection.
        't/T' indicates the first TCP payload retransmission from
        originator or responder, respectively.

    - Intelligence

        New field 'matched' to indicate which indicator type(s) caused the hit.

    - DNS

        New 'rtt' field to indicate the round trip time between when a
        request was sent and when a reply started.

    - SMTP

        New 'cc' field which includes the 'Cc' header from MIME
        messages sent over SMTP.

        Changes in 'mailfrom' and 'rcptto' fields to remove some
        non-address cruft that will tend to be found.  The main
        example is the change from ``"<user@domain>"`` to
        ``"user@domain.com"``.

    - HTTP

        Removed 'filename' field (which was seldomly used).

        New 'orig_filenames' and 'resp_filenames' fields which each
        contain a vector of filenames seen in entities transferred.

    - stats.log

        The following fields have been added: active_tcp_conns,
        active_udp_conns, active_icmp_conns, tcp_conns, udp_conns,
        icmp_conns, timers, active_timers, files, active_files, dns_requests,
        active_dns_requests, reassem_tcp_size, reassem_file_size,
        reassem_frag_size, reassem_unknown_size.

        The following fields have been renamed: lag -> pkt_lag.

        The following fields have been removed: pkts_recv.

- The BrokerComm and BrokerStore namespaces were renamed to Broker.
  The Broker "print()" function was renamed to Broker::send_print(), and
  the "event()" function was renamed to Broker::send_event().

- The constant ``SSH::skip_processing_after_detection`` was removed. The
  functionality was replaced by the new constant
  ``SSH::disable_analyzer_after_detection``.

- The ``net_stats()`` and ``resource_usage()`` functions have been
  removed, and their functionality is now provided by the new execution
  statistics functions (see above).

- Some script-level identifiers have changed their names:

      - snaplen                  -> Pcap::snaplen
      - precompile_pcap_filter() -> Pcap::precompile_pcap_filter()
      - install_pcap_filter()    -> Pcap::install_pcap_filter()
      - pcap_error()             -> Pcap::error()

- TCP analysis was changed to process connections without the initial
  SYN packet. In the past, connections without a full handshake were
  treated as partial, meaning that most application-layer analyzers
  would refuse to inspect the payload. Now, Bro will consider these
  connections as complete and all analyzers will process them normally.

- The ``policy/misc/capture-loss.bro`` script is now loaded by default.

- The traceroute detection script package ``policy/misc/detect-traceroute``
  is no longer loaded by default.

- Changed BroControl functionality in aux/broctl:

  - The networks.cfg file now contains private IP space 172.16.0.0/12
    by default.

  - Upon startup, if broctl can't get IP addresses from the "ifconfig"
    command for any reason, then broctl will now also try to use the
    "ip" command.

  - BroControl will now automatically search the Bro plugin directory
    for BroControl plugins (in addition to all the other places where
    BroControl searches).  This enables automatic loading of
    BroControl plugins that are provided by a Bro plugin.

  - Changed the default value of the StatusCmdShowAll option so that
    the "broctl status" command runs faster.  This also means that
    there is no longer a "Peers" column in the status output by
    default.

  - Users can now specify a more granular log expiration interval. The
    BroControl option LogExpireInterval can be set to an arbitrary
    time interval instead of just an integer number of days.  The time
    interval is specified as an integer followed by a time unit:
    "day", "hr", or "min".  For backward compatibility, an integer
    value without a time unit is still interpreted as a number of
    days.

  - Changed the text of crash report emails.  Now crash reports tell
    the user to forward the mail to the Bro team only when a backtrace
    is included in the crash report.  If there is no backtrace, then
    the crash report includes instructions on how to get backtraces
    included in future crash reports.

  - There is a new option SitePolicyScripts that replaces SitePolicyStandalone
    (the old option is still available, but will be removed in the next
    release).

Removed Functionality
---------------------

- The app-stats scripts have been removed because they weren't
  being maintained and they were becoming inaccurate (as a result, the
  app_stats.log is also gone). They were also prone to needing more regular
  updates as the internet changed and will likely be more relevant if
  maintained externally.

- The event ack_above_hole() has been removed, as it was a subset
  of content_gap() and led to plenty of noise.

- The command line options ``--analyze``, ``--set-seed``, and
  ``--md5-hashkey`` have been removed.

- The packaging scripts pkg/make-\*-packages are gone. They aren't
  used anymore for the binary Bro packages that the project
  distributes; haven't been supported in a while; and have
  problems.

Deprecated Functionality
------------------------

- The built-in functions decode_base64_custom() and
  encode_base64_custom() are no longer needed and will be removed
  in the future. Their functionality is now provided directly by
  decode_base64() and encode_base64(), which take an optional
  parameter to change the Base64 alphabet.

Bro 2.4
=======

New Functionality
-----------------

- Bro now has support for external plugins that can extend its core
  functionality, like protocol/file analysis, via shared libraries.
  Plugins can be developed and distributed externally, and will be
  pulled in dynamically at startup (the environment variables
  BRO_PLUGIN_PATH and BRO_PLUGIN_ACTIVATE can be used to specify the
  locations and names of plugins to activate). Currently, a plugin
  can provide custom protocol analyzers, file analyzers, log writers,
  input readers, packet sources and dumpers, and new built-in functions.
  A plugin can furthermore hook into Bro's processing at a number of
  places to add custom logic.

  See https://www.bro.org/sphinx-git/devel/plugins.html for more
  information on writing plugins.

- Bro now has support for the MySQL wire protocol. Activity gets
  logged into mysql.log.

- Bro now parses DTLS traffic. Activity gets logged into ssl.log.

- Bro now has support for the Kerberos KRB5 protocol over TCP and
  UDP. Activity gets logged into kerberos.log.

- Bro now has an RDP analyzer. Activity gets logged into rdp.log.

- Bro now has a file analyzer for Portable Executables. Activity gets
  logged into pe.log.

- Bro now has support for the SIP protocol over UDP. Activity gets
  logged into sip.log.

- Bro now features a completely rewritten, enhanced SSH analyzer.  The
  new analyzer is able to determine if logins failed or succeeded in
  most circumstances, logs a lot more more information about SSH
  sessions, supports v1, and introduces the intelligence type
  ``Intel::PUBKEY_HASH`` and location ``SSH::IN_SERVER_HOST_KEY``. The
  analayzer also generates a set of additional events
  (``ssh_auth_successful``, ``ssh_auth_failed``, ``ssh_auth_attempted``,
  ``ssh_auth_result``, ``ssh_capabilities``, ``ssh2_server_host_key``,
  ``ssh1_server_host_key``, ``ssh_encrypted_packet``,
  ``ssh2_dh_server_params``, ``ssh2_gss_error``, ``ssh2_ecc_key``). See
  next section for incompatible SSH changes.

- Bro's file analysis now supports reassembly of files that are not
  transferred/seen sequentially.  The default file reassembly buffer
  size is set with the ``Files::reassembly_buffer_size`` variable.

- Bro's file type identification has been greatly improved (new file types,
  bug fixes, and performance improvements).

- Bro's scripting language now has a ``while`` statement::

        while ( i < 5 )
            print ++i;

  ``next`` and ``break`` can be used inside the loop's body just like
  with ``for`` loops.

- Bro now integrates Broker, a new communication library. See
  aux/broker/README for more information on Broker, and
  doc/frameworks/broker.rst for the corresponding Bro script API.

  With Broker, Bro has the similar capabilities of exchanging events and
  logs with remote peers (either another Bro process or some other
  application that uses Broker).  It also includes a key-value store
  API that can be used to share state between peers and optionally
  allow data to persist on disk for longer-term storage.

  Broker support is by default off for now; it can be enabled at
  configure time with --enable-broker. It requires CAF version 0.13+
  (https://github.com/actor-framework/actor-framework) as well as a
  C++11 compiler (e.g. GCC 4.8+ or Clang 3.3+).

  Broker will become a mandatory dependency in future Bro versions and
  replace the current communication and serialization system.

- Add --enable-c++11 configure flag to compile Bro's source code in
  C++11 mode with a corresponding compiler. Note that 2.4 will be the
  last version of Bro that compiles without C++11 support.

- The SSL analysis now alerts when encountering SSL connections with
  old protocol versions or unsafe cipher suites. It also gained
  extended reporting of weak keys, caching of already validated
  certificates, and full support for TLS record defragmentation. SSL generally
  became much more robust and added several fields to ssl.log (while
  removing some others).

- A new icmp_sent_payload event provides access to ICMP payload.

- The input framework's raw reader now supports seeking by adding an
  option "offset" to the config map. Positive offsets are interpreted
  to be from the beginning of the file, negative from the end of the
  file (-1 is end of file).

- One can now raise events when a connection crosses a given size
  threshold in terms of packets or bytes. The primary API for that
  functionality is in base/protocols/conn/thresholds.bro.

- There is a new command-line option -Q/--time that prints Bro's execution
  time and memory usage to stderr.

- BroControl now has a new command "deploy" which is equivalent to running
  the "check", "install", "stop", and "start" commands (in that order).

- BroControl now has a new option "StatusCmdShowAll" that controls whether
  or not the broctl "status" command gathers all of the status information.
  This option can be used to make the "status" command run significantly
  faster (in this case, the "Peers" column will not be shown in the output).

- BroControl now has a new option "StatsLogEnable" that controls whether
  or not broctl will record information to the "stats.log" file.  This option
  can be used to make the "broctl cron" command run slightly faster (in this
  case, "broctl cron" will also no longer send email about not seeing any
  packets on the monitoring interfaces).

- BroControl now has a new option "MailHostUpDown" which controls whether or
  not the "broctl cron" command will send email when it notices that a host
  in the cluster is up or down.

- BroControl now has a new option "CommandTimeout" which specifies the number
  of seconds to wait for a command that broctl ran to return results.

Changed Functionality
---------------------

- bro-cut has been rewritten in C, and is hence much faster.

- File analysis

    * Removed ``fa_file`` record's ``mime_type`` and ``mime_types``
      fields.  The event ``file_sniff`` has been added which provides
      the same information.  The ``mime_type`` field of ``Files::Info``
      also still has this info.

    * The earliest point that new mime type information is available is
      in the ``file_sniff`` event which comes after the ``file_new`` and
      ``file_over_new_connection`` events.  Scripts which inspected mime
      type info within those events will need to be adapted.  (Note: for
      users that worked w/ versions of Bro from git, for a while there was
      also an event called ``file_mime_type`` which is now replaced with
      the ``file_sniff`` event).

    * Removed ``Files::add_analyzers_for_mime_type`` function.

    * Removed ``offset`` parameter of the ``file_extraction_limit``
      event.  Since file extraction now internally depends on file
      reassembly for non-sequential files, "offset" can be obtained
      with other information already available -- adding together
      ``seen_bytes`` and ``missed_bytes`` fields of the ``fa_file``
      record gives how many bytes have been written so far (i.e.
      the "offset").

- The SSH changes come with a few incompatibilities. The following
  events have been renamed:

    * ``SSH::heuristic_failed_login`` to ``ssh_auth_failed``
    * ``SSH::heuristic_successful_login`` to ``ssh_auth_successful``

  The ``SSH::Info`` status field has been removed and replaced with
  the ``auth_success`` field.  This field has been changed from a
  string that was previously ``success``, ``failure`` or
  ``undetermined`` to a boolean. a boolean that is ``T``, ``F``, or
  unset.

- The has_valid_octets function now uses a string_vec parameter instead of
  string_array.

- conn.log gained a new field local_resp that works like local_orig,
  just for the responder address of the connection.

- GRE tunnels are now identified as ``Tunnel::GRE`` instead of
  ``Tunnel::IP``.

- The default name for extracted files changed from extract-protocol-id
  to extract-timestamp-protocol-id.

- The weird named "unmatched_HTTP_reply" has been removed since it can
  be detected at the script-layer and is handled correctly by the
  default HTTP scripts.

- When adding a logging filter to a stream, the filter can now inherit
  a default ``path`` field from the associated ``Log::Stream`` record.

- When adding a logging filter to a stream, the
  ``Log::default_path_func`` is now only automatically added to the
  filter if it has neither a ``path`` nor a ``path_func`` already
  explicitly set.  Before, the default path function would always be set
  for all filters which didn't specify their own ``path_func``.

- BroControl now establishes only one ssh connection from the manager to
  each remote host in a cluster configuration (previously, there would be
  one ssh connection per remote Bro process).

- BroControl now uses SQLite to record state information instead of a
  plain text file (the file "spool/broctl.dat" is no longer used).
  On FreeBSD, this means that there is a new dependency on the package
  "py27-sqlite3".

- BroControl now records the expected running state of each Bro node right
  before each start or stop.  The "broctl cron" command uses this info to
  either start or stop Bro nodes as needed so that the actual state matches
  the expected state (previously, "broctl cron" could only start nodes in
  the "crashed" state, and could never stop a node).

- BroControl now sends all normal command output (i.e., not error messages)
  to stdout.  Error messages are still sent to stderr, however.

- The capability of processing NetFlow input has been removed for the
  time being.  Therefore, the -y/--flowfile and -Y/--netflow command-line
  options have been removed, and the netflow_v5_header and netflow_v5_record
  events have been removed.

- The -D/--dfa-size command-line option has been removed.

- The -L/--rule-benchmark command-line option has been removed.

- The -O/--optimize command-line option has been removed.

- The deprecated fields "hot" and "addl" have been removed from the
  connection record. Likewise, the functions append_addl() and
  append_addl_marker() have been removed.

- Log files now escape non-printable characters consistently as "\xXX'.
  Furthermore, backslashes are escaped as "\\", making the
  representation fully reversible.

Deprecated Functionality
------------------------

- The split* family of functions are to be replaced with alternate
  versions that return a vector of strings rather than a table of
  strings. This also allows deprecation for some related string
  concatenation/extraction functions. Note that the new functions use
  0-based indexing, rather than 1-based.

  The full list of now deprecated functions is:

    * split: use split_string instead.

    * split1: use split_string1 instead.

    * split_all: use split_string_all instead.

    * split_n: use split_string_n instead.

    * cat_string_array: see join_string_vec instead.

    * cat_string_array_n: see join_string_vec instead.

    * join_string_array: see join_string_vec instead.

    * sort_string_array: use sort instead.

    * find_ip_addresses: use extract_ip_addresses instead.

Bro 2.3
=======

Dependencies
------------

- Libmagic is no longer a dependency.

New Functionality
-----------------

- Support for GRE tunnel decapsulation, including enhanced GRE
  headers. GRE tunnels are treated just like IP-in-IP tunnels by
  parsing past the GRE header in between the delivery and payload IP
  packets.

- The DNS analyzer now actually generates the dns_SRV_reply() event.
  It had been documented before, yet was never raised.

- Bro now uses "file magic signatures" to identify file types. These
  are defined via two new constructs in the signature rule parsing
  grammar: "file-magic" gives a regular expression to match against,
  and "file-mime" gives the MIME type string of content that matches
  the magic and an optional strength value for the match. (See also
  "Changed Functionality" below for changes due to switching from
  using libmagic to such signatures.)

- A new built-in function, "file_magic", can be used to get all file
  magic matches and their corresponding strength against a given chunk
  of data.

- The SSL analyzer now supports heartbeats as well as a few
  extensions, including server_name, alpn, and ec-curves.

- The SSL analyzer comes with Heartbleed detector script in
  protocols/ssl/heartbleed.bro.  Note that loading this script changes
  the default value of "SSL::disable_analyzer_after_detection" from true
  to false to prevent encrypted heartbeats from being ignored.

- StartTLS is now supported for SMTP and POP3.

- The X509 analyzer can now perform OSCP validation.

- Bro now has analyzers for SNMP and Radius, which produce corresponding
  snmp.log and radius.log output (as well as various events of course).

- BroControl has a new option "BroPort" which allows a user to specify
  the starting port number for Bro.

- BroControl has a new option "StatsLogExpireInterval" which allows a
  user to specify when entries in the stats.log file expire.

- BroControl has a new option "PFRINGClusterType" which allows a user
  to specify a PF_RING cluster type.

- BroControl now supports PF_RING+DNA.  There is also a new option
  "PFRINGFirstAppInstance" that allows a user to specify the starting
  application instance number for processes running on a DNA cluster.
  See the BroControl documentation for more details.

- BroControl now warns a user to run "broctl install" if Bro has
  been upgraded or if the broctl or node configuration has changed
  since the most recent install.

Changed Functionality
---------------------

- string slices now exclude the end index (e.g., "123"[1:2] returns
  "2"). Generally, Bro's string slices now behave similar to Python.

- ssl_client_hello() now receives a vector of ciphers, instead of a
  set, to preserve their order.

- Notice::end_suppression() has been removed.

- Bro now parses X.509 extensions headers and, as a result, the
  corresponding event got a new signature:

      event x509_extension(c: connection, is_orig: bool, cert: X509, ext: X509_extension_info);

- In addition, there are several new, more specialized events for a
  number of x509 extensions.

- Generally, all x509 events and handling functions have changed their
  signatures.

- X509 certificate verification now returns the complete certificate
  chain that was used for verification.

- Bro no longer special-cases SYN/FIN/RST-filtered traces by not
  reporting missing data. Instead, if Bro never sees any data segments
  for analyzed TCP connections, the new
  base/misc/find-filtered-trace.bro script will log a warning in
  reporter.log and to stderr.  The old behavior can be reverted by
  redef'ing "detect_filtered_trace".

- We have removed the packet sorter component.

- Bro no longer uses libmagic to identify file types but instead now
  comes with its own signature library (which initially is still
  derived from libmagic's database). This leads to a number of further
  changes with regards to MIME types:

    * The second parameter of the "identify_data" built-in function
      can no longer be used to get verbose file type descriptions,
      though it can still be used to get the strongest matching file
      magic signature.

    * The "file_transferred" event's "descr" parameter no longer
      contains verbose file type descriptions.

    * The BROMAGIC environment variable no longer changes any behavior
      in Bro as magic databases are no longer used/installed.

    * Removed "binary" and "octet-stream" mime type detections. They
      don't provide any more information than an uninitialized
      mime_type field.

    * The "fa_file" record now contains a "mime_types" field that
      contains all magic signatures that matched the file content
      (where the "mime_type" field is just a shortcut for the
      strongest match).

- dns_TXT_reply() now supports more than one string entry by receiving
  a vector of strings.

- BroControl now runs the "exec" and "df" broctl commands only once
  per host, instead of once per Bro node.  The output of these
  commands has been changed slightly to include both the host and
  node names.

- Several performance improvements were made.  Particular emphasis
  was put on the File Analysis system, which generally will now emit
  far fewer file handle request events due to protocol analyzers now
  caching that information internally.

Bro 2.2
=======

New Functionality
-----------------

- A completely overhauled intelligence framework for consuming
  external intelligence data. It provides an abstracted mechanism
  for feeding data into the framework to be matched against the
  data available. It also provides a function named ``Intel::match``
  which makes any hits on intelligence data available to the
  scripting language.

  Using input framework, the intel framework can load data from
  text files. It can also update and add data if changes are
  made to the file being monitored. Files to monitor for
  intelligence can be provided by redef-ing the
  ``Intel::read_files`` variable.

  The intel framework is cluster-ready. On a cluster, the
  manager is the only node that needs to load in data from disk,
  the cluster support will distribute the data across a cluster
  automatically.

  Scripts are provided at ``policy/frameworks/intel/seen`` that
  provide a broad set of sources of data to feed into the intel
  framwork to be matched.

- A new file analysis framework moves most of the processing of file
  content from script-land into the core, where it belongs. See
  ``doc/file-analysis.rst``, or the online documentation, for more
  information.

  Much of this is an internal change, but the framework also comes
  with the following user-visible functionality (some of that was
  already available before but is done differently, and more
  efficiently, now):

      - HTTP:

        * Identify MIME type of messages.
        * Extract messages to disk.
        * Compute MD5 for messages.

      - SMTP:

        * Identify MIME type of messages.
        * Extract messages to disk.
        * Compute MD5 for messages.
        * Provide access to start of entity data.

      - FTP data transfers:

        * Identify MIME types of data.
        * Record to disk.

      - IRC DCC transfers: Record to disk.

      - Support for analyzing data transferred via HTTP range requests.

      - A binary input reader interfaces the input framework with the
        file analysis, allowing to inject files on disk into Bro's
        content processing.

- A new framework for computing a wide array of summary statistics,
  such as counters and thresholds checks, standard deviation and mean,
  set cardinality, top K, and more. The framework operates in
  real-time, independent of the underlying data, and can aggregate
  information from many independent monitoring points (including
  clusters). It provides a transparent, easy-to-use user interface,
  and can optionally deploy a set of probabilistic data structures for
  memory-efficient operation. The framework is located in
  ``scripts/base/frameworks/sumstats``.

  A number of new applications now ship with Bro that are built on top
  of the summary statistics framework:

    * Scan detection: Detectors for port and address scans. See
      ``policy/misc/scan.bro`` (these scan detectors used to exist in
      Bro versions <2.0; it's now back, but quite different).

    * Tracerouter detector: ``policy/misc/detect-traceroute.bro``

    * Web application detection/measurement:
      ``policy/misc/app-stats/*``

    * FTP and SSH brute-forcing detector:
      ``policy/protocols/ftp/detect-bruteforcing.bro``,
      ``policy/protocols/ssh/detect-bruteforcing.bro``

    * HTTP-based SQL injection detector:
      ``policy/protocols/http/detect-sqli.bro`` (existed before, but
      now ported to the new framework)

- GridFTP support. This is an extension to the standard FTP analyzer
  and includes:

      - An analyzer for the GSI mechanism of GSSAPI FTP AUTH method.
        GSI authentication involves an encoded TLS/SSL handshake over
        the FTP control session. For FTP sessions that attempt GSI
        authentication, the ``service`` field of the connection log
        will include ``gridftp`` (as well as also ``ftp`` and
        ``ssl``).

      - An example of a GridFTP data channel detection script. It
        relies on the heuristics of GridFTP data channels commonly
        default to SSL mutual authentication with a NULL bulk cipher
        and that they usually transfer large datasets (default
        threshold of script is 1 GB). For identified GridFTP data
        channels, the ``services`` fields of the connection log will
        include ``gridftp-data``.

- Modbus and DNP3 support. Script-level support is only basic at this
  point but see ``src/analyzer/protocol/{modbus,dnp3}/events.bif``, or
  the online documentation, for the events Bro generates. For Modbus,
  there are also some example policies in
  ``policy/protocols/modbus/*``.

- The documentation now includes a new introduction to writing Bro
  scripts. See ``doc/scripting/index.rst`` or, much better, the online
  version. There's also the beginning of a chapter on "Using Bro" in
  ``doc/using/index.rst``.

- GPRS Tunnelling Protocol (GTPv1) decapsulation.

- The scripting language now provide "hooks", a new flavor of
  functions that share characteristics of both standard functions and
  events. They are like events in that multiple bodies can be defined
  for the same hook identifier. They are more like functions in the
  way they are invoked/called, because, unlike events, their execution
  is immediate and they do not get scheduled through an event queue.
  Also, a unique feature of a hook is that a given hook handler body
  can short-circuit the execution of remaining hook handlers simply by
  exiting from the body as a result of a ``break`` statement (as
  opposed to a ``return`` or just reaching the end of the body). See
  ``doc/scripts/builtins.rst``, or the online documentation, for more
  informatin.

- Bro's language now has a working ``switch`` statement that generally
  behaves like C-style switches (except that case labels can be
  comprised of multiple literal constants delimited by commas).  Only
  atomic types are allowed for now.  Case label bodies that don't
  execute a ``return`` or ``break`` statement will fall through to
  subsequent cases. A ``default`` case label is supported.

- Bro's language now has a new set of types ``opaque of X``. Opaque
  values can be passed around like other values but they can only be
  manipulated with BiF functions, not with other operators. Currently,
  the following opaque types are supported::

        opaque of md5
        opaque of sha1
        opaque of sha256
        opaque of cardinality
        opaque of topk
        opaque of bloomfilter

  These go along with the corrsponding BiF functions ``md5_*``,
  ``sha1_*``, ``sha256_*``, ``entropy_*``, etc. . Note that where
  these functions existed before, they have changed their signatures
  to work with opaques types rather than global state.

- The scripting language now supports constructing sets, tables,
  vectors, and records by name::

        type MyRecordType: record {
            c: count;
            s: string &optional;
        };

        global r: MyRecordType = record($c = 7);

        type MySet: set[MyRec];
        global s = MySet([$c=1], [$c=2]);

- Strings now support the subscript operator to extract individual
  characters and substrings (e.g., ``s[4]``, ``s[1:5]``). The index
  expression can take up to two indices for the start and end index of
  the substring to return (e.g. ``mystring[1:3]``).

- Functions now support default parameters, e.g.::

      global foo: function(s: string, t: string &default="abc", u: count &default=0);

- Scripts can now use two new "magic constants" ``@DIR`` and
  ``@FILENAME`` that expand to the directory path of the current
  script and just the script file name without path, respectively.

- ``ssl.log`` now also records the subject client and issuer
  certificates.

- The ASCII writer can now output CSV files on a per filter basis.

- New SQLite reader and writer plugins for the logging framework allow
  to read/write persistent data from on disk SQLite databases.

- A new packet filter framework supports BPF-based load-balancing,
  shunting, and sampling; plus plugin support to customize filters
  dynamically.

- Bro now provides Bloom filters of two kinds: basic Bloom filters
  supporting membership tests, and counting Bloom filters that track
  the frequency of elements. The corresponding functions are::

    bloomfilter_basic_init(fp: double, capacity: count, name: string &default=""): opaque of bloomfilter
    bloomfilter_basic_init2(k: count, cells: count, name: string &default=""): opaque of bloomfilter
    bloomfilter_counting_init(k: count, cells: count, max: count, name: string &default=""): opaque of bloomfilter
    bloomfilter_add(bf: opaque of bloomfilter, x: any)
    bloomfilter_lookup(bf: opaque of bloomfilter, x: any): count
    bloomfilter_merge(bf1: opaque of bloomfilter, bf2: opaque of bloomfilter): opaque of bloomfilter
    bloomfilter_clear(bf: opaque of bloomfilter)

  See ``src/probabilistic/bloom-filter.bif``, or the online
  documentation, for full documentation.

- Bro now provides a probabilistic data structure for computing
  "top k" elements. The corresponding functions are::

    topk_init(size: count): opaque of topk
    topk_add(handle: opaque of topk, value: any)
    topk_get_top(handle: opaque of topk, k: count)
    topk_count(handle: opaque of topk, value: any): count
    topk_epsilon(handle: opaque of topk, value: any): count
    topk_size(handle: opaque of topk): count
    topk_sum(handle: opaque of topk): count
    topk_merge(handle1: opaque of topk, handle2: opaque of topk)
    topk_merge_prune(handle1: opaque of topk, handle2: opaque of topk)

  See ``src/probabilistic/top-k.bif``, or the online documentation,
  for full documentation.

- Bro now provides a probabilistic data structure for computing set
  cardinality, using the HyperLogLog algorithm.  The corresponding
  functions are::

    hll_cardinality_init(err: double, confidence: double): opaque of cardinality
    hll_cardinality_add(handle: opaque of cardinality, elem: any): bool
    hll_cardinality_merge_into(handle1: opaque of cardinality, handle2: opaque of cardinality): bool
    hll_cardinality_estimate(handle: opaque of cardinality): double
    hll_cardinality_copy(handle: opaque of cardinality): opaque of cardinality

  See ``src/probabilistic/cardinality-counter.bif``, or the online
  documentation, for full documentation.

- ``base/utils/exec.bro`` provides a module to start external
  processes asynchronously and retrieve their output on termination.
  ``base/utils/dir.bro`` uses it to monitor a directory for changes,
  and ``base/utils/active-http.bro`` for providing an interface for
  querying remote web servers.

- BroControl can now pin Bro processes to CPUs on supported platforms:
  To use CPU pinning, a new per-node option ``pin_cpus`` can be
  specified in node.cfg if the OS is either Linux or FreeBSD.

- BroControl now returns useful exit codes.  Most BroControl commands
  return 0 if everything was OK, and 1 otherwise.  However, there are
  a few exceptions.  The "status" and "top" commands return 0 if all Bro
  nodes are running, and 1 if not all nodes are running.  The "cron"
  command always returns 0 (but it still sends email if there were any
  problems).  Any command provided by a plugin always returns 0.

- BroControl now has an option "env_vars" to set Bro environment variables.
  The value of this option is a comma-separated list of environment variable
  assignments (e.g., "VAR1=value, VAR2=another").  The "env_vars" option
  can apply to all Bro nodes (by setting it in broctl.cfg), or can be
  node-specific (by setting it in node.cfg).  Environment variables in
  node.cfg have priority over any specified in broctl.cfg.

- BroControl now supports load balancing with PF_RING while sniffing
  multiple interfaces.  Rather than assigning the same PF_RING cluster ID
  to all workers on a host, cluster ID assignment is now based on which
  interface a worker is sniffing (i.e., all workers on a host that sniff
  the same interface will share a cluster ID).  This is handled by
  BroControl automatically.

- BroControl has several new options:  MailConnectionSummary (for
  disabling the sending of connection summary report emails),
  MailAlarmsInterval (for specifying a different interval to send alarm
  summary emails), CompressCmd (if archived log files will be compressed,
  this specifies the command that will be used to compress them),
  CompressExtension (if archived log files will be compressed, this
  specifies the file extension to use).

- BroControl comes with its own test-suite now. ``make test`` in
  ``aux/broctl`` will run it.

In addition to these, Bro 2.2 comes with a large set of smaller
extensions, tweaks, and fixes across the whole code base, including
most submodules.

Changed Functionality
---------------------

- Previous versions of ``$prefix/share/bro/site/local.bro`` (where
  "$prefix" indicates the installation prefix of Bro), aren't compatible
  with Bro 2.2.  This file won't be overwritten when installing over a
  previous Bro installation to prevent clobbering users' modifications,
  but an example of the new version is located in
  ``$prefix/share/bro/site/local.bro.example``.  So if no modification
  has been done to the previous local.bro, just copy the new example
  version over it, else merge in the differences.  For reference,
  a common error message when attempting to use an outdated local.bro
  looks like::

    fatal error in /usr/local/bro/share/bro/policy/frameworks/software/vulnerable.bro, line 41: BroType::AsRecordType (table/record) (set[record { min:record { major:count; minor:count; minor2:count; minor3:count; addl:string; }; max:record { major:count; minor:count; minor2:count; minor3:count; addl:string; }; }])

- The type of ``Software::vulnerable_versions`` changed to allow
  more flexibility and range specifications.  An example usage:

  .. code:: bro

        const java_1_6_vuln = Software::VulnerableVersionRange(
            $max = Software::Version($major = 1, $minor = 6, $minor2 = 0, $minor3 = 44)
        );

        const java_1_7_vuln = Software::VulnerableVersionRange(
            $min = Software::Version($major = 1, $minor = 7),
            $max = Software::Version($major = 1, $minor = 7, $minor2 = 0, $minor3 = 20)
        );

        redef Software::vulnerable_versions += {
            ["Java"] = set(java_1_6_vuln, java_1_7_vuln)
        };

- The interface to extracting content from application-layer protocols
  (including HTTP, SMTP, FTP) has changed significantly due to the
  introduction of the new file analysis framework (see above).

- Removed the following, already deprecated, functionality:

    * Scripting language:
        - ``&disable_print_hook attribute``.

    * BiF functions:
        - ``parse_dotted_addr()``, ``dump_config()``,
          ``make_connection_persistent()``, ``generate_idmef()``,
          ``split_complete()``

        - ``md5_*``, ``sha1_*``, ``sha256_*``, and ``entropy_*`` have
          all changed their signatures to work with opaque types (see
          above).

- Removed a now unused argument from ``do_split`` helper function.

- ``this`` is no longer a reserved keyword.

- The Input Framework's ``update_finished`` event has been renamed to
  ``end_of_data``. It will now not only fire after table-reads have
  been completed, but also after the last event of a whole-file-read
  (or whole-db-read, etc.).

- Renamed the option defining the frequency of alarm summary mails to
  ``Logging::default_alarm_mail_interval``. When using BroControl, the
  value can now be set with the new broctl.cfg option
  ``MailAlarmsInterval``.

- We have completely rewritten the ``notice_policy`` mechanism. It now
  no longer uses a record of policy items but a ``hook``, a new
  language element that's roughly equivalent to a function with
  multiple bodies (see above). For existing code, the two main changes
  are:

    - What used to be a ``redef`` of ``Notice::policy`` now becomes a
      hook implementation. Example:

      Old::

        redef Notice::policy += {
            [$pred(n: Notice::Info) = {
                return n$note == SSH::Login && n$id$resp_h == 10.0.0.1;
                },
            $action = Notice::ACTION_EMAIL]
            };

      New::

        hook Notice::policy(n: Notice::Info)
            {
            if ( n$note == SSH::Login && n$id$resp_h == 10.0.0.1 )
                add n$actions[Notice::ACTION_EMAIL];
            }

    - notice() is now likewise a hook, no longer an event. If you
      have handlers for that event, you'll likely just need to change
      the type accordingly. Example:

      Old::

        event notice(n: Notice::Info) { ... }

      New::

        hook notice(n: Notice::Info) { ... }

- The ``notice_policy.log`` is gone. That's a result of the new notice
  policy setup.

- Removed the ``byte_len()`` and ``length()`` bif functions. Use the
  ``|...|`` operator instead.

- The ``SSH::Login`` notice has been superseded by an corresponding
  intelligence framework observation (``SSH::SUCCESSFUL_LOGIN``).

- ``PacketFilter::all_packets`` has been replaced with
  ``PacketFilter::enable_auto_protocol_capture_filters``.

- We removed the BitTorrent DPD signatures pending further updates to
  that analyzer.

- In previous versions of BroControl, running "broctl cron" would create
  a file ``$prefix/logs/stats/www`` (where "$prefix" indicates the
  installation prefix of Bro).  Now, it is created as a directory.
  Therefore, if you perform an upgrade install and you're using BroControl,
  then you may see an email (generated by "broctl cron") containing an
  error message:  "error running update-stats".  To fix this problem,
  either remove that file (it is not needed) or rename it.

- Due to lack of maintenance the Ruby bindings for Broccoli are now
  deprecated, and the build process no longer includes them by
  default. For the time being, they can still be enabled by
  configuring with ``--enable-ruby``, however we plan to remove
  Broccoli's Ruby support with the next Bro release.

Bro 2.1
=======

New Functionality
-----------------

- Bro now comes with extensive IPv6 support. Past versions offered
  only basic IPv6 functionality that was rarely used in practice as it
  had to be enabled explicitly. IPv6 support is now fully integrated
  into all parts of Bro including protocol analysis and the scripting
  language. It's on by default and no longer requires any special
  configuration.

  Some of the most significant enhancements include support for IPv6
  fragment reassembly, support for following IPv6 extension header
  chains, and support for tunnel decapsulation (6to4 and Teredo). The
  DNS analyzer now handles AAAA records properly, and DNS lookups that
  Bro itself performs now include AAAA queries, so that, for example,
  the result returned by script-level lookups is a set that can
  contain both IPv4 and IPv6 addresses. Support for the most common
  ICMPv6 message types has been added. Also, the FTP EPSV and EPRT
  commands are now handled properly. Internally, the way IP addresses
  are stored has been improved, so Bro can handle both IPv4
  and IPv6 by default without any special configuration.

  In addition to Bro itself, the other Bro components have also been
  made IPv6-aware by default. In particular, significant changes were
  made to trace-summary, PySubnetTree, and Broccoli to support IPv6.

- Bro now decapsulates tunnels via its new tunnel framework located in
  scripts/base/frameworks/tunnels. It currently supports Teredo,
  AYIYA, IP-in-IP (both IPv4 and IPv6), and SOCKS. For all these, it
  logs the outer tunnel connections in both conn.log and tunnel.log,
  and then proceeds to analyze the inner payload as if it were not
  tunneled, including also logging that session in conn.log. For
  SOCKS, it generates a new socks.log in addition with more
  information.

- Bro now features a flexible input framework that allows users to
  integrate external information in real-time into Bro while it's
  processing network traffic. The most direct use-case at the moment
  is reading data from ASCII files into Bro tables, with updates
  picked up automatically when the file changes during runtime. See
  doc/input.rst for more information.

  Internally, the input framework is structured around the notion of
  "reader plugins" that make it easy to interface to different data
  sources. We will add more in the future.

- BroControl now has built-in support for host-based load-balancing
  when using either PF_RING, Myricom cards, or individual interfaces.
  Instead of adding a separate worker entry in node.cfg for each Bro
  worker process on each worker host, it is now possible to just
  specify the number of worker processes on each host and BroControl
  configures everything correctly (including any neccessary enviroment
  variables for the balancers).

  This change adds three new keywords to the node.cfg file (to be used
  with worker entries): lb_procs (specifies number of workers on a
  host), lb_method (specifies what type of load balancing to use:
  pf_ring, myricom, or interfaces), and lb_interfaces (used only with
  "lb_method=interfaces" to specify which interfaces to load-balance
  on).

- Bro's default ASCII log format is not exactly the most efficient way
  for storing and searching large volumes of data. An alternatives,
  Bro now comes with experimental support for two alternative output
  formats:

    * DataSeries: an efficient binary format for recording structured
      bulk data. DataSeries is developed and maintained at HP Labs.
      See doc/logging-dataseries for more information.

    * ElasticSearch: a distributed RESTful, storage engine and search
      engine built on top of Apache Lucene. It scales very well, both
      for distributed indexing and distributed searching. See
      doc/logging-elasticsearch.rst for more information.

  Note that at this point, we consider Bro's support for these two
  formats as prototypes for collecting experience with alternative
  outputs. We do not yet recommend them for production (but welcome
  feedback!)


Changed Functionality
---------------------

The following summarizes the most important differences in existing
functionality. Note that this list is not complete, see CHANGES for
the full set.

- Changes in dependencies:

    * Bro now requires CMake >= 2.6.3.

    * On Linux, Bro now links in tcmalloc (part of Google perftools)
      if found at configure time. Doing so can significantly improve
      memory and CPU use.

      On the other platforms, the new configure option
      --enable-perftools can be used to enable linking to tcmalloc.
      (Note that perftools's support for non-Linux platforms may be
      less reliable).

- The configure switch --enable-brov6 is gone.

- DNS name lookups performed by Bro now also query AAAA records. The
  results of the A and AAAA queries for a given hostname are combined
  such that at the scripting layer, the name resolution can yield a
  set with both IPv4 and IPv6 addresses.

- The connection compressor was already deprecated in 2.0 and has now
  been removed from the code base.

- We removed the "match" statement, which was no longer used by any of
  the default scripts, nor was it likely to be used by anybody anytime
  soon. With that, "match" and "using" are no longer reserved keywords.

- The syntax for IPv6 literals changed from "2607:f8b0:4009:802::1012"
  to "[2607:f8b0:4009:802::1012]". When an IP address variable or IP
  address literal is enclosed in pipes (for example,
  ``|[fe80::db15]|``) the result is now the size of the address in
  bits (32 for IPv4 and 128 for IPv6).

- Bro now spawns threads for doing its logging. From a user's
  perspective not much should change, except that the OS may now show
  a bunch of Bro threads.

- We renamed the configure option --enable-perftools to
  --enable-perftools-debug to indicate that the switch is only relevant
  for debugging the heap.

- Bro's ICMP analyzer now handles both IPv4 and IPv6 messages with a
  joint set of events.  The `icmp_conn` record got a new boolean field
  'v6' that indicates whether the ICMP message is v4 or v6.

- Log postprocessor scripts get an additional argument indicating the
  type of the log writer in use (e.g., "ascii").

- BroControl's make-archive-name script also receives the writer
  type, but as its 2nd(!) argument. If you're using a custom version
  of that script, you need to adapt it. See the shipped version for
  details.

- Signature files can now be loaded via the new "@load-sigs"
  directive. In contrast to the existing (and still supported)
  signature_files constant, this can be used to load signatures
  relative to the current script (e.g., "@load-sigs ./foo.sig").

- The options "tunnel_port" and "parse_udp_tunnels" have been removed.
  Bro now supports decapsulating tunnels directly for protocols it
  understands.

- ASCII logs now record the time when they were opened/closed at the
  beginning and end of the file, respectively (wall clock). The
  options LogAscii::header_prefix and LogAscii::include_header have
  been renamed to LogAscii::meta_prefix and LogAscii::include_meta,
  respectively.

- The ASCII writers "header_*" options have been renamed to "meta_*"
  (because there's now also a footer).

- Some built-in functions have been removed: "addr_to_count" (use
  "addr_to_counts" instead), "bro_has_ipv6" (this is no longer
  relevant because Bro now always supports IPv6), "active_connection"
  (use "connection_exists" instead), and "connection_record" (use
  "lookup_connection" instead).

- The "NFS3::mode2string" built-in function has been renamed to
  "file_mode".

- Some built-in functions have been changed: "exit" (now takes the
  exit code as a parameter), "to_port" (now takes a string as
  parameter instead of a count and transport protocol, but
  "count_to_port" is still available), "connect" (now takes an
  additional string parameter specifying the zone of a non-global IPv6
  address), and "listen" (now takes three additional parameters to
  enable listening on IPv6 addresses).

- Some Bro script variables have been renamed:
  "LogAscii::header_prefix" has been renamed to
  "LogAscii::meta_prefix", "LogAscii::include_header" has been renamed
  to "LogAscii::include_meta".

- Some Bro script variables have been removed: "tunnel_port",
  "parse_udp_tunnels", "use_connection_compressor",
  "cc_handle_resets", "cc_handle_only_syns", and
  "cc_instantiate_on_data".

- A couple events have changed: the "icmp_redirect" event now includes
  the target and destination addresses and any Neighbor Discovery
  options in the message, and the last parameter of the
  "dns_AAAA_reply" event has been removed because it was unused.

- The format of the ASCII log files has changed very slightly.  Two
  new lines are automatically added, one to record the time when the
  log was opened, and the other to record the time when the log was
  closed.

- In BroControl, the option (in broctl.cfg) "CFlowAddr" was renamed to
  "CFlowAddress".


Bro 2.0
=======

As the version number jump from 1.5 suggests, Bro 2.0 is a major
upgrade and lots of things have changed. Most importantly, we have
rewritten almost all of Bro's default scripts from scratch, using
quite different structure now and focusing more on operational
deployment. The result is a system that works much better "out of the
box", even without much initial site-specific configuration. The
down-side is that 1.x configurations will need to be adapted to work
with the new version. The two rules of thumb are:

    (1) If you have written your own Bro scripts
        that do not depend on any of the standard scripts formerly
        found in ``policy/``, they will most likely just keep working
        (although you might want to adapt them to use some of the new
        features, like the new logging framework; see below).

    (2) If you have custom code that depends on specifics of 1.x
        default scripts (including most configuration tuning), that is
        unlikely to work with 2.x. We recommend to start by using just
        the new scripts first, and then port over any customizations
        incrementally as necessary (they may be much easier to do now,
        or even unnecessary). Send mail to the Bro user mailing list
        if you need help.

Below we summarize changes from 1.x to 2.x in more detail. This list
isn't complete, see the ``CHANGES`` file in the distribution.
for the full story.

Script Organization
-------------------

In versions before 2.0, Bro scripts were all maintained in a flat
directory called ``policy/`` in the source tree.  This directory is now
renamed to ``scripts/`` and contains major subdirectories ``base/``,
``policy/``, and ``site/``, each of which may also be subdivided
further.

The contents of the new ``scripts/`` directory, like the old/flat
``policy/`` still gets installed under the ``share/bro``
subdirectory of the installation prefix path just like previous
versions.  For example, if Bro was compiled like ``./configure
--prefix=/usr/local/bro && make && make install``, then the script
hierarchy can be found in ``/usr/local/bro/share/bro``.

The main
subdirectories of that hierarchy are as follows:

- ``base/`` contains all scripts that are loaded by Bro by default
  (unless the ``-b`` command line option is used to run Bro in a
  minimal configuration). Note that is a major conceptual change:
  rather than not loading anything by default, Bro now uses an
  extensive set of default scripts out of the box.

  The scripts under this directory generally either accumulate/log
  useful state/protocol information for monitored traffic, configure a
  default/recommended mode of operation, or provide extra Bro
  scripting-layer functionality that has no significant performance cost.

- ``policy/`` contains all scripts that a user will need to explicitly
  tell Bro to load.  These are scripts that implement
  functionality/analysis that not all users may want to use and may have
  more significant performance costs. For a new installation, you
  should go through these and see what appears useful to load.

- ``site/`` remains a directory that can be used to store locally
  developed scripts. It now comes with some preinstalled example
  scripts that contain recommended default configurations going beyond
  the ``base/`` setup. E.g. ``local.bro`` loads extra scripts from
  ``policy/`` and does extra tuning. These files can be customized in
  place without being overwritten by upgrades/reinstalls, unlike
  scripts in other directories.

With version 2.0, the default ``BROPATH`` is set to automatically
search for scripts in ``policy/``, ``site/`` and their parent
directory, but **not** ``base/``.  Generally, everything under
``base/`` is loaded automatically, but for users of the ``-b`` option,
it's important to know that loading a script in that directory
requires the extra ``base/`` path qualification.  For example, the
following two scripts:

* ``$PREFIX/share/bro/base/protocols/ssl/main.bro``
* ``$PREFIX/share/bro/policy/protocols/ssl/validate-certs.bro``

are referenced from another Bro script like:

.. code:: bro

    @load base/protocols/ssl/main
    @load protocols/ssl/validate-certs

Notice how ``policy/`` can be omitted as a convenience in the second
case. ``@load`` can now also use relative path, e.g., ``@load
../main``.


Logging Framework
-----------------

- The logs generated by scripts that ship with Bro are entirely redone
  to use a standardized, machine parsable format via the new logging
  framework. Generally, the log content has been restructured towards
  making it more directly useful to operations. Also, several
  analyzers have been significantly extended and thus now log more
  information. Take a look at ``ssl.log``.

  * A particular format change that may be useful to note is that the
    ``conn.log`` ``service`` field is derived from DPD instead of
    well-known ports (while that was already possible in 1.5, it was
    not the default).

  * Also, ``conn.log`` now reports raw number of packets/bytes per
    endpoint.

- The new logging framework makes it possible to extend, customize,
  and filter logs very easily.

- A common pattern found in the new scripts is to store logging stream
  records for protocols inside the ``connection`` records so that
  state can be collected until enough is seen to log a coherent unit
  of information regarding the activity of that connection.  This
  state is now frequently seen/accessible in event handlers, for
  example, like ``c$<protocol>`` where ``<protocol>`` is replaced by
  the name of the protocol.  This field is added to the ``connection``
  record by ``redef``'ing it in a
  ``base/protocols/<protocol>/main.bro`` script.

- The logging code has been rewritten internally, with script-level
  interface and output backend now clearly separated. While ASCII
  logging is still the default, we will add further output types in
  the future (binary format, direct database logging).


Notice Framework
----------------

The way users interact with "notices" has changed significantly in order
to make it easier to define a site policy and more extensible for adding
customized actions.


New Default Settings
--------------------

- Dynamic Protocol Detection (DPD) is now enabled/loaded by default.

- The default packet filter now examines all packets instead of
  dynamically building a filter based on which protocol analysis scripts
  are loaded. See ``PacketFilter::all_packets`` for how to revert to old
  behavior.

API Changes
-----------

- The ``@prefixes`` directive works differently now.
  Any added prefixes are now searched for and loaded *after* all input
  files have been parsed.  After all input files are parsed, Bro
  searches ``BROPATH`` for prefixed, flattened versions of all of the
  parsed input files.  For example, if ``lcl`` is in ``@prefixes``, and
  ``site.bro`` is loaded, then a file named ``lcl.site.bro`` that's in
  ``BROPATH`` would end up being automatically loaded as well.  Packages
  work similarly, e.g. loading ``protocols/http`` means a file named
  ``lcl.protocols.http.bro`` in ``BROPATH`` gets loaded automatically.

- The ``make_addr`` BIF now returns a ``subnet`` versus an ``addr``


Variable Naming
---------------

- ``Module`` is more widely used for namespacing. E.g. the new
  ``site.bro`` exports the ``local_nets`` identifier (among other
  things) into the ``Site`` module.

- Identifiers may have been renamed to conform to new `scripting
  conventions
  <http://www.bro.org/development/howtos/script-conventions.html>`_


Removed Functionality
---------------------

We have remove a bunch of functionality that was rarely used and/or
had not been maintained for a while already:

    - The ``net`` script data type.
    - The ``alarm`` statement; use the notice framework instead.
    - Trace rewriting.
    - DFA state expiration in regexp engine.
    - Active mapping.
    - Native DAG support (may come back eventually)
    - ClamAV support.
    - The connection compressor is now disabled by default, and will
      be removed in the future.

BroControl Changes
------------------

BroControl looks pretty much similar to the version coming with Bro 1.x,
but has been cleaned up and streamlined significantly internally.

BroControl has a new ``process`` command to process a trace on disk
offline using a similar configuration to what BroControl installs for
live analysis.

BroControl now has an extensive plugin interface for adding new
commands and options. Note that this is still considered experimental.

We have removed the ``analysis`` command, and BroControl currently
does not send daily alarm summaries anymore (this may be restored
later).

Development Infrastructure
--------------------------

Bro development has moved from using SVN to Git for revision control.
Users that want to use the latest Bro development snapshot by checking it out
from the source repositories should see the `development process
<http://www.bro.org/development/process.html>`_. Note that all the various
sub-components now reside in their own repositories. However, the
top-level Bro repository includes them as git submodules so it's easy
to check them all out simultaneously.

Bro now uses `CMake <http://www.cmake.org>`_ for its build system so
that is a new required dependency when building from source.

Bro now comes with a growing suite of regression tests in
``testing/``.
