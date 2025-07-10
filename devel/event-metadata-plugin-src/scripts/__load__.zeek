module EventLatency;

redef enum EventMetadata::ID += {
	## The absolute timestamp at which this event was published.
	WALLCLOCK_TIMESTAMP = 10001000,
};

event zeek_init()
	{
	assert EventMetadata::register(WALLCLOCK_TIMESTAMP, time);
	}
