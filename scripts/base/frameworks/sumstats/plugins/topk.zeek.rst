:tocdepth: 3

base/frameworks/sumstats/plugins/topk.zeek
==========================================
.. zeek:namespace:: SumStats

Keep the top-k (i.e., most frequently occurring) observations.

:Namespace: SumStats
:Imports: :doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`

Summary
~~~~~~~
Redefinitions
#############
===================================================== ======================================================================================
:zeek:type:`SumStats::Calculation`: :zeek:type:`enum` 
                                                      
                                                      * :zeek:enum:`SumStats::TOPK`:
                                                        Keep a top-k list of values.
:zeek:type:`SumStats::Reducer`: :zeek:type:`record`   
                                                      
                                                      :New Fields: :zeek:type:`SumStats::Reducer`
                                                      
                                                        topk_size: :zeek:type:`count` :zeek:attr:`&default` = ``500`` :zeek:attr:`&optional`
                                                          Number of elements to keep in the top-k list.
:zeek:type:`SumStats::ResultVal`: :zeek:type:`record` 
                                                      
                                                      :New Fields: :zeek:type:`SumStats::ResultVal`
                                                      
                                                        topk: :zeek:type:`opaque` of topk :zeek:attr:`&optional`
                                                          A handle which can be passed to some built-in functions to get
                                                          the top-k results.
===================================================== ======================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

