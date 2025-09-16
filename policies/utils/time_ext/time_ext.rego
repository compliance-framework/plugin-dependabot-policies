package utils.time_ext

one_day_ns := ((24 * 60) * 60) * 1e9

reduce_day_ns(ns) := ns if {
	day := time.weekday(ns)
	day != "Sunday"
	day != "Saturday"
}

reduce_day_ns(ns) := working_day_ns if {
	day := time.weekday(ns)
	day == "Sunday"
	working_day_ns := ns - (2 * one_day_ns)
}

reduce_day_ns(ns) := working_day_ns if {
	day := time.weekday(ns)
	day == "Saturday"
	working_day_ns := ns - one_day_ns
}
