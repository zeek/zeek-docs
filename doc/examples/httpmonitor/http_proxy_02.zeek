
module HTTP;

export {

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
	if ( /^[hH][tT][tT][pP]:/ in c$http$uri &&
	     c$http$status_code in HTTP::success_status_codes )
		print fmt("A local server is acting as an open proxy: %s", c$id$resp_h);
	}
