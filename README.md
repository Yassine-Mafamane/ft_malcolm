# ft_malcolm

## Overview
ft_malcolm is part of the 42 security projects. It is a learning project to understand man-in-the-middle (MITM) attacks and ARP spoofing. The main reference is RFC 826 (ARP): https://www.rfc-editor.org/rfc/pdfrfc/rfc826.txt.pdf

## Why ARP Is Weak
ARP has no authentication or integrity checks. Any host can claim to own an IP address, and many systems will accept ARP replies without verifying the sender. This makes it possible for an attacker to poison ARP tables and redirect traffic.

## Project Idea
The goal is to attempt to poison the ARP table of a victim (or a group of victims). The project provides multiple attack modes to fit different conditions (some trigger after an ARP request is seen on the wire), and an optional HTTP proxy mode to visualize the effect (one request/response only).

## Attack Modes
- Reply spoofing (default): send forged ARP replies to poison the target.
- Reply flooding (-f): send many forged replies.
- Reply spoofing (solicited) (-s): respond to ARP requests, useful when unsolicited replies are ignored.
- Request spoofing (-r): send forged ARP requests.
- Interface-wide spoofing (-i): target all hosts on the interface (requires only source IP/MAC).

## Build
```sh
make
```

## Usage
This program uses `AF_PACKET`, so it must be run with sudo.
```sh
sudo ./ft_malcolm [options] <source IP> <source MAC> <target IP> <target MAC>
```

Options:
- `-h` : Display help and exit
- `-f` : ARP reply flooding
- `-s` : ARP reply spoofing (solicited)
- `-r` : ARP request spoofing
- `-i` : Interface-wide ARP spoofing (expects only <source IP> <source MAC>)
- `-v` : Verbose mode
- `-p` : Proxy HTTP communication after spoofing (one request/response, then exit)

## Examples
Default reply spoofing:
```sh
sudo ./ft_malcolm <src_ip> <src_mac> <target_ip> <target_mac>
```

Solicited reply spoofing:
```sh
sudo ./ft_malcolm -s <src_ip> <src_mac> <target_ip> <target_mac>
```

Interface-wide spoofing:
```sh
sudo ./ft_malcolm -i <src_ip> <src_mac>
```

## Lab Setup Notes
It is recommended to run this project in a virtual machine lab. Use one VM as the attacker and one or more VMs as victims, all on the same virtual network.

Some systems do not accept unsolicited ARP messages. On the victim side, you can allow them with:
```sh
sysctl -w net.ipv4.conf.all.arp_accept=1
```

If you use the HTTP proxy mode, set this iptables rule on the attacker before running the program so traffic to port 4242 is redirected to the local proxy:
```sh
iptables -t nat -A PREROUTING -p tcp --dport 4242 -j REDIRECT --to-port 4242
```
This rule ensures that intercepted HTTP traffic reaches the proxy, so you can see a single request and response.

## Safety
Use only in controlled environments and on systems you are authorized to test.
