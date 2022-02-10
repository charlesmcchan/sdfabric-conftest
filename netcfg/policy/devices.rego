package main

deny[msg] {
	not input["devices"]
	msg = "Must have devices section"
}

deny[msg] {
    device = input["devices"][_]
    not device["segmentrouting"]
    msg = "Every device must have segmentrouting config"
}

deny[msg] {
    device = input["devices"][_]
    not device["segmentrouting"]["ipv4NodeSid"]
    msg = "Every device must have ipv4NodeSid"
}

deny[msg] {
    device = input["devices"][_]
    not device["segmentrouting"]["ipv4Loopback"]
    msg = "Every device must have ipv4Loopback"
}

deny[msg] {
    device = input["devices"][_]
    not device["segmentrouting"]["routerMac"]
    msg = "Every device must have routerMac"
}

warn[msg] {
    device = input["devices"][_]
    not device["segmentrouting"]["pairDeviceId"]
    msg = "Some devices don't have pairDeviceId"
}

warn[msg] {
    device = input["devices"][_]
    not device["segmentrouting"]["pairLocalPort"]
    msg = "Some devices don't have pairLocalPort"
}

deny[msg] {
    device = input["devices"][_]
    not device["segmentrouting"]["isEdgeRouter"]
    msg = "Every device must have isEdgeRouter"
}

deny[msg] {
    device = input["devices"][_]
    not device["segmentrouting"]["adjacencySids"]
    msg = "Every device must have adjacencySids"
}

deny[msg] {
    device = input["devices"][_]
    count(device["segmentrouting"]["adjacencySids"]) != 0
    msg = "adjacencySids must be an empty array"
}
