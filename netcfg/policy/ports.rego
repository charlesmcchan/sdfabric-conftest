package main

deny[msg] {
	not input["ports"]
	msg = "Must have ports section"
}

deny[msg] {
    port = input["ports"][_]
    not port["interfaces"]
    msg = "Every port must have interfaces section"
}

warn[msg] {
    port = input["ports"][_]
    count(port["interfaces"]) != 1
    msg = "Every port should have just one interface"
}

deny[msg] {
    interfaces = input["ports"][_]["interfaces"]
    not interfaces[0]
    msg = "First interface should be an array"
}

deny[msg] {
    intf = input["ports"][_]["interfaces"][0]
    not intf["ips"]
    msg = "IP should be an array"
}

deny[msg] {
    intf = input["ports"][_]["interfaces"][0]
    count(intf["ips"]) < 1
    msg = "Every interface should have at least one IP"
}

deny[msg] {
    port = input["ports"][_]
    interface = port["interfaces"][0]
    not interface["vlan-untagged"]; not interface["vlan-tagged"];
    msg = "Every interface should be vlan-untagged or vlan-tagged"
}

deny[msg] {
    port = input["ports"][_]
    interface = port["interfaces"][0]
    not interface["name"]
    msg = "Every interface should have a name"
}