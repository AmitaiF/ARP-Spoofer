# ARP Spoofer
A CLI tool for performing ARP Spoofing.

## What is ARP Spoofing?
In computer networking, ARP spoofing, ARP cache poisoning, or ARP poison routing, is a technique by which an
attacker sends (spoofed) Address Resolution Protocol (ARP) messages onto a local area network. Generally,
the aim is to associate the attacker's MAC address with the IP address of another host, such as the default
gateway, causing any traffic meant for that IP address to be sent to the attacker instead.  
*(from [Wikipedia](https://en.wikipedia.org/wiki/ARP_spoofing))*


## Installation
1. Download the project. You can download a zip file, or you can clone it:
```
git clone https://github.com/AmitaiF/ARP-Spoofer.git
```
2. Install requirements.txt:
```
pip install -r requirements.txt
```

## Usage
```
C:\>arpspoofer.py -h
usage: arpspoofer.py [-h] [-i IFACE] [-s SRC] [-d DELAY] [-gw] -t TARGET

Spoof ARP tables

optional arguments:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        Interface you wish to use
  -s SRC, --src SRC     The address you want for the attacker
  -d DELAY, --delay DELAY
                        Delay (in seconds) between messages
  -gw                   should GW be attacked as well?
  -t TARGET, --target TARGET
                        IP of target

Example:
 for making 10.0.0.12 think we are the gateway:
     python arpspoofer.py -t 10.0.0.12
 for making 10.0.0.12 think we are the gateway, and the the gateway think we are 10.0.0.12:
     python arpspoofer.py -t 10.0.0.12 -gw
```

## How it works?
Assuming we want the victim to think we are the gateway. In order to do this, the program constantly
sends the victim 'is_at' responses, which say that the mac address of the gateway is our mac address.  
If we want, we can also make the gateway think we are the victim, by sending him 'is_at' which says
that the victim mac is ours.  
If we do this, we are now performing a MITM (Man In The Middle) attack, and we can filter and change all the traffic between them.
