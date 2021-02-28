# TC IPIP Mapper (WIP)
## Description
A project aimed to add support for multiple remotes on an IPIP tunnel. This project consist of two TC programs (one for ingress and the other for egress).

The main goal of the TC ingress program is to map the client IP (inner IP header's source IP address) to the remote IP (the outer IP header's source address).

When outgoing IPIP packets are sent back out, it will replace the outer IP header's destination IP address with the mapped remote IP if it exist. If it doesn't, the packet will go out unchanged.

An example where this is useful is if you're utilizing IPIP tunnels with an Anycast network and want the traffic to go back the same POP server it came in with.

## Command Line Usage
The only command line option is `-i --dev` which determines which interface to attach to. An example of using the `ipipmapper` loader may be found below.

```
./ipipmapper --dev ens18
```

## Credits
* [Christian Deacon](https://github.com/gamemann)