:tocdepth: 3

policy/misc/unknown-protocols.zeek
==================================
.. zeek:namespace:: UnknownProtocol

This script logs information about packet protocols that Zeek doesn't
know how to process. Mostly these come from packet analysis plugins when
they attempt to forward to the next analyzer, but they also can originate
from non-packet analyzers.

:Namespace: UnknownProtocol
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

Summary
~~~~~~~
Redefinable Options
###################
======================================================================================== =======================================================================
:zeek:id:`UnknownProtocol::first_bytes_count`: :zeek:type:`count` :zeek:attr:`&redef`    The number of bytes to extract from the next header and log in the
                                                                                         first bytes field.
:zeek:id:`UnknownProtocol::sampling_duration`: :zeek:type:`interval` :zeek:attr:`&redef` How long an analyzer/protocol pair is allowed to keep state/counters in
                                                                                         in memory.
:zeek:id:`UnknownProtocol::sampling_rate`: :zeek:type:`count` :zeek:attr:`&redef`        The rate-limiting sampling rate.
:zeek:id:`UnknownProtocol::sampling_threshold`: :zeek:type:`count` :zeek:attr:`&redef`   How many reports for an analyzer/protocol pair will be allowed to
                                                                                         raise events before becoming rate-limited.
======================================================================================== =======================================================================

Types
#####
======================================================= =
:zeek:type:`UnknownProtocol::Info`: :zeek:type:`record` 
======================================================= =

Redefinitions
#############
======================================= ===================================
:zeek:type:`Log::ID`: :zeek:type:`enum` 
                                        
                                        * :zeek:enum:`UnknownProtocol::LOG`
======================================= ===================================

Hooks
#####
==================================================================== =
:zeek:id:`UnknownProtocol::log_policy`: :zeek:type:`Log::PolicyHook` 
==================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: UnknownProtocol::first_bytes_count

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10``

   The number of bytes to extract from the next header and log in the
   first bytes field.

.. zeek:id:: UnknownProtocol::sampling_duration

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 hr``

   How long an analyzer/protocol pair is allowed to keep state/counters in
   in memory. Once the threshold has been hit, this is the amount of time
   before the rate-limiting for a pair expires and is reset.

.. zeek:id:: UnknownProtocol::sampling_rate

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100000``

   The rate-limiting sampling rate. One out of every of this number of
   rate-limited pairs of a given type will be allowed to raise events
   for further script-layer handling. Setting the sampling rate to 0
   will disable all output of rate-limited pairs.

.. zeek:id:: UnknownProtocol::sampling_threshold

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``3``

   How many reports for an analyzer/protocol pair will be allowed to
   raise events before becoming rate-limited.

Types
#####
.. zeek:type:: UnknownProtocol::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when the measurement occurred.

      analyzer: :zeek:type:`string` :zeek:attr:`&log`
         The string name of the analyzer attempting to forward the protocol.

      protocol_id: :zeek:type:`string` :zeek:attr:`&log`
         The identifier of the protocol being forwarded.

      first_bytes: :zeek:type:`string` :zeek:attr:`&log`
         A certain number of bytes at the start of the unknown protocol's
         header.


Hooks
#####
.. zeek:id:: UnknownProtocol::log_policy

   :Type: :zeek:type:`Log::PolicyHook`



