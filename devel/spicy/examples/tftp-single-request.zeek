event tftp::request(c: connection)
	{
	print "TFTP request", c$id;
	}

event zeek_init()
	{
	Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_TFTP, set(69/udp));
	}
