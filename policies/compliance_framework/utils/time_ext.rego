package compliance_framework.utils.time_ext

ONE_DAY_NS := 24 * 60 * 60 * 1e9

reduce_day_ns(ns) = working_day_ns if {
	day := time.weekday(ns)
	day != "Sunday"
	day != "Saturday"
	working_day_ns := ns
}

reduce_day_ns(ns) = working_day_ns if {
	day := time.weekday(ns)
	day == "Sunday"
	working_day_ns := ns - (2 * ONE_DAY_NS)
}

reduce_day_ns(ns) = working_day_ns if {
	day := time.weekday(ns)
	day == "Saturday"
	working_day_ns := ns - ONE_DAY_NS 
}