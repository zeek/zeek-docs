@load base/utils/site
@load base/frameworks/notice

redef Site::local_nets += { 192.168.0.0/16 };

module HTTP;

export {

	redef enum Notice::Type += {
		Open_Proxy
	};

	global success_status_codes: set[count] = {
		200,
		201,
		202,
		203,
		204,
		205,
		206,
		207,
		208,
		226,
		304
	};
}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if ( Site::is_local_addr(c$id$resp_h) &&
	     /^[hH][tT][tT][pP]:/ in c$http$uri &&
	     c$http$status_code in HTTP::success_status_codes )
		NOTICE([$note=HTTP::Open_Proxy,
		        $msg=fmt("A local server is acting as an open proxy: %s",
		                 c$id$resp_h),
		        $conn=c,
		        $identifier=cat(c$id$resp_h),
		        $suppress_for=1day]);
	}
