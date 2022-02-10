package main

warn[msg] {
	not input["apps"]["org.onosproject.route-service"]["routes"]
	msg = "Static route not configured"
}

deny[msg] {
	routes = input["apps"]["org.onosproject.route-service"]["routes"]
    count(routes) < 1
	msg = "Route array empty"
}

deny[msg] {
	route = input["apps"]["org.onosproject.route-service"]["routes"][_]
    not route["prefix"]
	msg = "Every static route must have prefix"
}

deny[msg] {
	route = input["apps"]["org.onosproject.route-service"]["routes"][_]
    not route["nextHop"]
	msg = "Every static route must have nexthop"
}
