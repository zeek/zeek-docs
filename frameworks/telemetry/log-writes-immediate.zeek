global log_writes_cf = Telemetry::register_counter_family([
	$prefix="zeek",
	$name="log_writes",
	$unit="1",
	$helptext="Number of log writes per stream",
	$labels=vector("log_id")
]);

hook Log::log_stream_policy(rec: any, id: Log::ID)
	{
	local log_id = to_lower(gsub(cat(id), /:+/, "_"));
	Telemetry::counter_family_inc(log_writes_cf, vector(log_id));
	}
