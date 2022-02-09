:tocdepth: 3

policy/frameworks/cluster/controller/request.zeek
=================================================
.. zeek:namespace:: ClusterController::Request

This module implements a request state abstraction that both cluster
controller and agent use to tie responses to received request events and be
able to time-out such requests.

:Namespace: ClusterController::Request
:Imports: :doc:`policy/frameworks/cluster/controller/config.zeek </scripts/policy/frameworks/cluster/controller/config.zeek>`, :doc:`policy/frameworks/cluster/controller/types.zeek </scripts/policy/frameworks/cluster/controller/types.zeek>`

Summary
~~~~~~~
State Variables
###############
================================================================================================= ==========================================================
:zeek:id:`ClusterController::Request::null_req`: :zeek:type:`ClusterController::Request::Request` A token request that serves as a null/nonexistant request.
================================================================================================= ==========================================================

Types
#####
===================================================================== ====================================================================
:zeek:type:`ClusterController::Request::Request`: :zeek:type:`record` Request records track state associated with a request/response event
                                                                      pair.
===================================================================== ====================================================================

Events
######
========================================================================== ===================================================================
:zeek:id:`ClusterController::Request::request_expired`: :zeek:type:`event` This event fires when a request times out (as per the
                                                                           ClusterController::request_timeout) before it has been finished via
                                                                           ClusterController::Request::finish().
========================================================================== ===================================================================

Functions
#########
======================================================================= ========================================================================
:zeek:id:`ClusterController::Request::create`: :zeek:type:`function`    This function establishes request state.
:zeek:id:`ClusterController::Request::finish`: :zeek:type:`function`    This function marks a request as complete and causes Zeek to release
                                                                        its internal state.
:zeek:id:`ClusterController::Request::is_null`: :zeek:type:`function`   This function is a helper predicate to indicate whether a given
                                                                        request is null.
:zeek:id:`ClusterController::Request::lookup`: :zeek:type:`function`    This function looks up the request for a given request ID and returns
                                                                        it.
:zeek:id:`ClusterController::Request::to_string`: :zeek:type:`function` For troubleshooting, this function renders a request record to a string.
======================================================================= ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: ClusterController::Request::null_req
   :source-code: policy/frameworks/cluster/controller/request.zeek 36 36

   :Type: :zeek:type:`ClusterController::Request::Request`
   :Default:

      ::

         {
            id=""
            parent_id=<uninitialized>
            results=[]
            finished=T
            supervisor_state=<uninitialized>
            set_configuration_state=<uninitialized>
            get_nodes_state=<uninitialized>
            test_state=<uninitialized>
         }


   A token request that serves as a null/nonexistant request.

Types
#####
.. zeek:type:: ClusterController::Request::Request
   :source-code: policy/frameworks/cluster/controller/request.zeek 17 33

   :Type: :zeek:type:`record`

      id: :zeek:type:`string`
         Each request has a hopfully unique ID provided by the requester.

      parent_id: :zeek:type:`string` :zeek:attr:`&optional`
         For requests that result based upon another request (such as when
         the controller sends requests to agents based on a request it
         received by the client), this specifies that original, "parent"
         request.

      results: :zeek:type:`ClusterController::Types::ResultVec` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         The results vector builds up the list of results we eventually
         send to the requestor when we have processed the request.

      finished: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         An internal flag to track whether a request is complete.

      supervisor_state: :zeek:type:`ClusterAgent::Runtime::SupervisorState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/cluster/agent/main.zeek` is loaded)


      set_configuration_state: :zeek:type:`ClusterController::Runtime::SetConfigurationState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/cluster/controller/main.zeek` is loaded)


      get_nodes_state: :zeek:type:`ClusterController::Runtime::GetNodesState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/cluster/controller/main.zeek` is loaded)


      test_state: :zeek:type:`ClusterController::Runtime::TestState` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/frameworks/cluster/controller/main.zeek` is loaded)


   Request records track state associated with a request/response event
   pair. Calls to
   :zeek:see:`ClusterController::Request::create` establish such state
   when an entity sends off a request event, while
   :zeek:see:`ClusterController::Request::finish` clears the state when
   a corresponding response event comes in, or the state times out.

Events
######
.. zeek:id:: ClusterController::Request::request_expired
   :source-code: policy/frameworks/cluster/controller/main.zeek 556 601

   :Type: :zeek:type:`event` (req: :zeek:type:`ClusterController::Request::Request`)

   This event fires when a request times out (as per the
   ClusterController::request_timeout) before it has been finished via
   ClusterController::Request::finish().
   

   :req: the request state that is expiring.
   

Functions
#########
.. zeek:id:: ClusterController::Request::create
   :source-code: policy/frameworks/cluster/controller/request.zeek 101 106

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string` :zeek:attr:`&default` = ``9Ye7pQPhuMe`` :zeek:attr:`&optional`) : :zeek:type:`ClusterController::Request::Request`

   This function establishes request state.
   

   :reqid: the identifier to use for the request.
   

.. zeek:id:: ClusterController::Request::finish
   :source-code: policy/frameworks/cluster/controller/request.zeek 116 127

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string`) : :zeek:type:`bool`

   This function marks a request as complete and causes Zeek to release
   its internal state. When the request does not exist, this does
   nothing.
   

   :reqid: the ID of the request state to releaase.
   

.. zeek:id:: ClusterController::Request::is_null
   :source-code: policy/frameworks/cluster/controller/request.zeek 129 135

   :Type: :zeek:type:`function` (request: :zeek:type:`ClusterController::Request::Request`) : :zeek:type:`bool`

   This function is a helper predicate to indicate whether a given
   request is null.
   

   :request: a Request record to check.
   

   :returns: T if the given request matches the null_req instance, F otherwise.
   

.. zeek:id:: ClusterController::Request::lookup
   :source-code: policy/frameworks/cluster/controller/request.zeek 108 114

   :Type: :zeek:type:`function` (reqid: :zeek:type:`string`) : :zeek:type:`ClusterController::Request::Request`

   This function looks up the request for a given request ID and returns
   it. When no such request exists, returns ClusterController::Request::null_req.
   

   :reqid: the ID of the request state to retrieve.
   

.. zeek:id:: ClusterController::Request::to_string
   :source-code: policy/frameworks/cluster/controller/request.zeek 137 156

   :Type: :zeek:type:`function` (request: :zeek:type:`ClusterController::Request::Request`) : :zeek:type:`string`

   For troubleshooting, this function renders a request record to a string.
   

   :request: the request to render.
   


