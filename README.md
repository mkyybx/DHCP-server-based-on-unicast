# DHCP-server-based-on-unicast
A DHCP server implemented by sending raw Ethernet frames.

Using the raw socket in the Kali Linux to deliver the unicast **DHCP offer** and **DHCP ack** frames.

## How to configure the server through *dhcp.config*

* Line 1: Network address pool, e.g. 172.16.0.0
* Line 2: Subnet mask, e.g. 24
* Line 3: Default gateway
* Line 4: Default DNS
* Line 5: Lease time, in seconds
* Line 6: Server ID
* Line 7: Renew time
* Line 8: Rebinding time
