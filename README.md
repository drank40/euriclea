## 👉 Euriclea 

This is a TCP/IP fingerprinter relying on the timestamps included in the TCP header meant for use in CTF competitions. It can be used both for real time filtering and a posteriori analysis.

## Structure

This project has two main packages for now, **nfqueue** and **extractor**.
### NFQUEUE
 The first is meant to connect to an nfqueue that can be created with a command such as :

```  
sudo iptables -A INPUT -p tcp --dport 5400 -j NFQUEUE
```

Then by setting the nfqueue number with the \-queue parameter of the go binary, each incoming packet on the specified port(s) will be processes as such:

- If no arguments are specified each packets is let through and its fingerprinted is logged
- with the -black argument a comma separated list of fingerprinting can be blacklisted, for example
	```
	./nfqueue -black "billowing-violet,fragrant-scene"  
	```
- The white arguments also takes comma separated fingerprints, that will **never** be blocked, which is useful to whitelist the game server
- Note that by default anyone sending flag ins is whitelisted dinamically

### EXTRACTOR

The extractor is used to extract fingerprints from stdin or a .pcap file. The file to be inspected is provided as the only plain arg ("-" for stdin)

It accepts the following flags:

- **-L** to list all the fingerprinting present in the pcap
- **-data** to show a brief summary of the payload
- **-bpf** to provide a Berkley Packet Filter to apply to the pcap
- **-r** to filter with a given regex
- **-white** to only show the packages with the given comma separated list of fingerprints
- **-black** to exclude the fingerprints given in the list
- **-F** to list the fingerprints by frequency


## Intended use

This tool is meant to filter out attackers in an envioroment where each connection goes through a NAT server. Traffic should be manually analyzed to find offending payloads and then they should be added to the blacklist

## Detailed explanation

More details can be found in this presentation :

[Fingerprinting TCP/IP](https://www.youtube.com/live/Ten8S50Fy7s?si=a_g25_KBYcbrRNOr&t=2633 "Title")

## Possible improvments

Blacklisting and whitelisting should be more dynamic and should be automatic up to a point