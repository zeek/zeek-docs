:tocdepth: 3

base/bif/telemetry.bif.zeek
===========================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Telemetry

Functions for accessing counter metrics from script land.

:Namespaces: GLOBAL, Telemetry

Summary
~~~~~~~
Functions
#########
============================================================================== =
:zeek:id:`Telemetry::__dbl_counter_family`: :zeek:type:`function`              
:zeek:id:`Telemetry::__dbl_counter_inc`: :zeek:type:`function`                 
:zeek:id:`Telemetry::__dbl_counter_metric_get_or_add`: :zeek:type:`function`   
:zeek:id:`Telemetry::__dbl_counter_singleton`: :zeek:type:`function`           
:zeek:id:`Telemetry::__dbl_counter_value`: :zeek:type:`function`               
:zeek:id:`Telemetry::__dbl_gauge_dec`: :zeek:type:`function`                   
:zeek:id:`Telemetry::__dbl_gauge_family`: :zeek:type:`function`                
:zeek:id:`Telemetry::__dbl_gauge_inc`: :zeek:type:`function`                   
:zeek:id:`Telemetry::__dbl_gauge_metric_get_or_add`: :zeek:type:`function`     
:zeek:id:`Telemetry::__dbl_gauge_singleton`: :zeek:type:`function`             
:zeek:id:`Telemetry::__dbl_gauge_value`: :zeek:type:`function`                 
:zeek:id:`Telemetry::__dbl_histogram_family`: :zeek:type:`function`            
:zeek:id:`Telemetry::__dbl_histogram_metric_get_or_add`: :zeek:type:`function` 
:zeek:id:`Telemetry::__dbl_histogram_observe`: :zeek:type:`function`           
:zeek:id:`Telemetry::__dbl_histogram_singleton`: :zeek:type:`function`         
:zeek:id:`Telemetry::__dbl_histogram_sum`: :zeek:type:`function`               
:zeek:id:`Telemetry::__int_counter_family`: :zeek:type:`function`              
:zeek:id:`Telemetry::__int_counter_inc`: :zeek:type:`function`                 
:zeek:id:`Telemetry::__int_counter_metric_get_or_add`: :zeek:type:`function`   
:zeek:id:`Telemetry::__int_counter_singleton`: :zeek:type:`function`           
:zeek:id:`Telemetry::__int_counter_value`: :zeek:type:`function`               
:zeek:id:`Telemetry::__int_gauge_dec`: :zeek:type:`function`                   
:zeek:id:`Telemetry::__int_gauge_family`: :zeek:type:`function`                
:zeek:id:`Telemetry::__int_gauge_inc`: :zeek:type:`function`                   
:zeek:id:`Telemetry::__int_gauge_metric_get_or_add`: :zeek:type:`function`     
:zeek:id:`Telemetry::__int_gauge_singleton`: :zeek:type:`function`             
:zeek:id:`Telemetry::__int_gauge_value`: :zeek:type:`function`                 
:zeek:id:`Telemetry::__int_histogram_family`: :zeek:type:`function`            
:zeek:id:`Telemetry::__int_histogram_metric_get_or_add`: :zeek:type:`function` 
:zeek:id:`Telemetry::__int_histogram_observe`: :zeek:type:`function`           
:zeek:id:`Telemetry::__int_histogram_singleton`: :zeek:type:`function`         
:zeek:id:`Telemetry::__int_histogram_sum`: :zeek:type:`function`               
============================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Telemetry::__dbl_counter_family
   :source-code: base/bif/telemetry.bif.zeek 31 31

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, labels: :zeek:type:`string_vec`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of dbl_counter_metric_family


.. zeek:id:: Telemetry::__dbl_counter_inc
   :source-code: base/bif/telemetry.bif.zeek 40 40

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of dbl_counter_metric, amount: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__dbl_counter_metric_get_or_add
   :source-code: base/bif/telemetry.bif.zeek 34 34

   :Type: :zeek:type:`function` (family: :zeek:type:`opaque` of dbl_counter_metric_family, labels: :zeek:type:`table_string_of_string`) : :zeek:type:`opaque` of dbl_counter_metric


.. zeek:id:: Telemetry::__dbl_counter_singleton
   :source-code: base/bif/telemetry.bif.zeek 37 37

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of dbl_counter_metric


.. zeek:id:: Telemetry::__dbl_counter_value
   :source-code: base/bif/telemetry.bif.zeek 43 43

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of dbl_counter_metric) : :zeek:type:`double`


.. zeek:id:: Telemetry::__dbl_gauge_dec
   :source-code: base/bif/telemetry.bif.zeek 80 80

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of dbl_gauge_metric, amount: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__dbl_gauge_family
   :source-code: base/bif/telemetry.bif.zeek 68 68

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, labels: :zeek:type:`string_vec`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of dbl_gauge_metric_family


.. zeek:id:: Telemetry::__dbl_gauge_inc
   :source-code: base/bif/telemetry.bif.zeek 77 77

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of dbl_gauge_metric, amount: :zeek:type:`double` :zeek:attr:`&default` = ``1.0`` :zeek:attr:`&optional`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__dbl_gauge_metric_get_or_add
   :source-code: base/bif/telemetry.bif.zeek 71 71

   :Type: :zeek:type:`function` (family: :zeek:type:`opaque` of dbl_gauge_metric_family, labels: :zeek:type:`table_string_of_string`) : :zeek:type:`opaque` of dbl_gauge_metric


.. zeek:id:: Telemetry::__dbl_gauge_singleton
   :source-code: base/bif/telemetry.bif.zeek 74 74

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of dbl_gauge_metric


.. zeek:id:: Telemetry::__dbl_gauge_value
   :source-code: base/bif/telemetry.bif.zeek 83 83

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of dbl_gauge_metric) : :zeek:type:`double`


.. zeek:id:: Telemetry::__dbl_histogram_family
   :source-code: base/bif/telemetry.bif.zeek 105 105

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, labels: :zeek:type:`string_vec`, bounds: :zeek:type:`double_vec`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of dbl_histogram_metric_family


.. zeek:id:: Telemetry::__dbl_histogram_metric_get_or_add
   :source-code: base/bif/telemetry.bif.zeek 108 108

   :Type: :zeek:type:`function` (family: :zeek:type:`opaque` of dbl_histogram_metric_family, labels: :zeek:type:`table_string_of_string`) : :zeek:type:`opaque` of dbl_histogram_metric


.. zeek:id:: Telemetry::__dbl_histogram_observe
   :source-code: base/bif/telemetry.bif.zeek 114 114

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of dbl_histogram_metric, measurement: :zeek:type:`double`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__dbl_histogram_singleton
   :source-code: base/bif/telemetry.bif.zeek 111 111

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, bounds: :zeek:type:`double_vec`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of dbl_histogram_metric


.. zeek:id:: Telemetry::__dbl_histogram_sum
   :source-code: base/bif/telemetry.bif.zeek 117 117

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of dbl_histogram_metric) : :zeek:type:`double`


.. zeek:id:: Telemetry::__int_counter_family
   :source-code: base/bif/telemetry.bif.zeek 14 14

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, labels: :zeek:type:`string_vec`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of int_counter_metric_family


.. zeek:id:: Telemetry::__int_counter_inc
   :source-code: base/bif/telemetry.bif.zeek 23 23

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of int_counter_metric, amount: :zeek:type:`int` :zeek:attr:`&default` = ``1`` :zeek:attr:`&optional`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__int_counter_metric_get_or_add
   :source-code: base/bif/telemetry.bif.zeek 17 17

   :Type: :zeek:type:`function` (family: :zeek:type:`opaque` of int_counter_metric_family, labels: :zeek:type:`table_string_of_string`) : :zeek:type:`opaque` of int_counter_metric


.. zeek:id:: Telemetry::__int_counter_singleton
   :source-code: base/bif/telemetry.bif.zeek 20 20

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of int_counter_metric


.. zeek:id:: Telemetry::__int_counter_value
   :source-code: base/bif/telemetry.bif.zeek 26 26

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of int_counter_metric) : :zeek:type:`int`


.. zeek:id:: Telemetry::__int_gauge_dec
   :source-code: base/bif/telemetry.bif.zeek 60 60

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of int_gauge_metric, amount: :zeek:type:`int` :zeek:attr:`&default` = ``1`` :zeek:attr:`&optional`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__int_gauge_family
   :source-code: base/bif/telemetry.bif.zeek 48 48

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, labels: :zeek:type:`string_vec`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of int_gauge_metric_family


.. zeek:id:: Telemetry::__int_gauge_inc
   :source-code: base/bif/telemetry.bif.zeek 57 57

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of int_gauge_metric, amount: :zeek:type:`int` :zeek:attr:`&default` = ``1`` :zeek:attr:`&optional`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__int_gauge_metric_get_or_add
   :source-code: base/bif/telemetry.bif.zeek 51 51

   :Type: :zeek:type:`function` (family: :zeek:type:`opaque` of int_gauge_metric_family, labels: :zeek:type:`table_string_of_string`) : :zeek:type:`opaque` of int_gauge_metric


.. zeek:id:: Telemetry::__int_gauge_singleton
   :source-code: base/bif/telemetry.bif.zeek 54 54

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of int_gauge_metric


.. zeek:id:: Telemetry::__int_gauge_value
   :source-code: base/bif/telemetry.bif.zeek 63 63

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of int_gauge_metric) : :zeek:type:`int`


.. zeek:id:: Telemetry::__int_histogram_family
   :source-code: base/bif/telemetry.bif.zeek 88 88

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, labels: :zeek:type:`string_vec`, bounds: :zeek:type:`int_vec`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of int_histogram_metric_family


.. zeek:id:: Telemetry::__int_histogram_metric_get_or_add
   :source-code: base/bif/telemetry.bif.zeek 91 91

   :Type: :zeek:type:`function` (family: :zeek:type:`opaque` of int_histogram_metric_family, labels: :zeek:type:`table_string_of_string`) : :zeek:type:`opaque` of int_histogram_metric


.. zeek:id:: Telemetry::__int_histogram_observe
   :source-code: base/bif/telemetry.bif.zeek 97 97

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of int_histogram_metric, measurement: :zeek:type:`int`) : :zeek:type:`bool`


.. zeek:id:: Telemetry::__int_histogram_singleton
   :source-code: base/bif/telemetry.bif.zeek 94 94

   :Type: :zeek:type:`function` (prefix: :zeek:type:`string`, name: :zeek:type:`string`, bounds: :zeek:type:`int_vec`, helptext: :zeek:type:`string` :zeek:attr:`&default` = ``"Zeek Script Metric"`` :zeek:attr:`&optional`, unit: :zeek:type:`string` :zeek:attr:`&default` = ``"1"`` :zeek:attr:`&optional`, is_sum: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`) : :zeek:type:`opaque` of int_histogram_metric


.. zeek:id:: Telemetry::__int_histogram_sum
   :source-code: base/bif/telemetry.bif.zeek 100 100

   :Type: :zeek:type:`function` (val: :zeek:type:`opaque` of int_histogram_metric) : :zeek:type:`int`



