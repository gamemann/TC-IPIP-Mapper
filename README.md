# TC IPIP Mapper (WIP)
## Description
A project aimed to add support for multiple remotes on an IPIP tunnel. This project consist of two TC programs (one for ingress and the other for egress).

The main goal of the TC ingress program is to map the client IP (inner IP header's source IP address) to the remote IP (the outer IP header's source address).

When outgoing IPIP packets are sent back out, it will replace the outer IP header's destination IP address with the mapped POP IP if it exist.

## Credits
* [Christian Deacon](https://github.com/gamemann)