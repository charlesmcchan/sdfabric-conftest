package main

warn[msg] {
	not input["apps"]["org.omecproject.up4"]["up4"]
	msg = "UP4 not configured"
}

deny[msg] {
    up4 = input["apps"]["org.omecproject.up4"]["up4"]
	count(up4["devices"]) < 1
	msg = "UP4 config should contain at least one device"
}

deny[msg] {
    up4 = input["apps"]["org.omecproject.up4"]["up4"]
	not up4["s1uAddr"]
	msg = "UP4 config should contain s1uAddr"
}

deny[msg] {
    up4 = input["apps"]["org.omecproject.up4"]["up4"]
	count(up4["uePools"]) < 1
	msg = "UP4 config should contain at least one prefix in uePools"
}
