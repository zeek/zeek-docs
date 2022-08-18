:tocdepth: 3

policy/frameworks/files/deprecated-txhosts-rxhosts-connuids.zeek
================================================================
.. zeek:namespace:: Files

This script can be used to add back the fields ``tx_hosts``, ``rx_hosts``
and ``conn_uids`` to the :zeek:see:`Files::Info` record and thereby also
back into the ``files.log``. These fields have been removed in Zeek 5.1
and replaced with the more commonly used ``uid`` and ``id`` fields.

It's only purpose is to provide an easy way to add back the fields such that
existing downstream processes continue to work without the need to adapt them.
This script will be removed with Zeek 6.1 at which point downstream processes
hopefully have switched over to use ``uid`` and ``id`` instead.

:Namespace: Files
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`

Summary
~~~~~~~
Redefinitions
#############
================================================================= =============================================================================================================================
:zeek:type:`Files::Info`: :zeek:type:`record` :zeek:attr:`&redef` 
                                                                  
                                                                  :New Fields: :zeek:type:`Files::Info`
                                                                  
                                                                    tx_hosts: :zeek:type:`set` [:zeek:type:`addr`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                                      If this file was transferred over a network
                                                                      connection this should show the host or hosts that
                                                                      the data sourced from.
                                                                  
                                                                    rx_hosts: :zeek:type:`set` [:zeek:type:`addr`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                                      If this file was transferred over a network
                                                                      connection this should show the host or hosts that
                                                                      the data traveled to.
                                                                  
                                                                    conn_uids: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                                      Connection UIDs over which the file was transferred.
================================================================= =============================================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

