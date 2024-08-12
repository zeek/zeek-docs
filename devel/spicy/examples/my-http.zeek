event MyHTTP::request_line(c: connection, method: string, uri: string, version: string)
	{
	print fmt("Zeek saw from %s: %s %s %s", c$id$orig_h, method, uri, version);
	}

event zeek_init()
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_MYHTTP, set(12345/tcp));
	}
