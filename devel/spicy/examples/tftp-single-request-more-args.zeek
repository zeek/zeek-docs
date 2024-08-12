event tftp::request(c: connection, is_orig: bool, filename: string, mode: string)
	{
	print "TFTP request", c$id, is_orig, filename, mode;
	}

event zeek_init()
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_TFTP, set(69/udp));
	}
