import argparse

def main():
	parser = argparse.ArgumentParser(description='Spoof ARP tables')
	parser.add_argument('-i', '--iface', type=str, help='Interface you wish to use')
	parser.add_argument('-s', '--src', type=str, help='The address you want for the attacker')        
	parser.add_argument('-d', '--delay', type=str, help='Delay (in seconds) between messages')
	parser.add_argument('-gw', help='should GW be attacked as well?', action='store_true')
	parser.add_argument('-t', '--target', type=str, help='IP of target', required=True)
	args = parser.parse_args()

if __name__ == "__main__":
	main()