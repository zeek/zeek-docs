event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if ( /^[hH][tT][tT][pP]:/ in c$http$uri && c$http$status_code == 200 )
		print fmt("A local server is acting as an open proxy: %s", c$id$resp_h);
	}
