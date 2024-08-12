event tftp::read_request(c: connection, is_orig: bool, filename: string, mode: string)
	{
	print "TFTP read request", c$id, is_orig, filename, mode;
	}

event tftp::write_request(c: connection, is_orig: bool, filename: string, mode: string)
	{
	print "TFTP write request", c$id, is_orig, filename, mode;
	}

event zeek_init()
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_TFTP, set(69/udp));
	}
