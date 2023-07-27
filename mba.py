import json
from header import *
import socket
import pandas
class MBA:
    def __init__(self, myID, myIP, mal_IDs, mal_IPs, blacklisted_IPs, neigh_IPs, quarantine_periods, debug=True):
        self.myID = myID
        self.myIP = myIP
        self.mal_IDs = mal_IDs
        self.mal_IPs = mal_IPs
        self.blacklisted_IPs = blacklisted_IPs
        self.neigh_IPs = neigh_IPs
        self.quarantine_periods = quarantine_periods
        self.debug = debug

    def create_mba_message(self):
        # Function to create a new MBA message when a node discovers one or more malicious nodes
        # TODO: exclude nodes that are blacklisted and exclude other malicious nodes?
        to_send_IPs = list(set(self.neigh_IPs) - set(self.mal_IPs.values()) - set(self.blacklisted_IPs)) # 1 hop neighbors that are not malicious
        to_send_IPs.sort() # sorting in ascending order for test

        if to_send_IPs:
            message = {
                "Subject": "MBA",
                "Malicious_ID": self.mal_IDs,
                "Malicious_IP": self.mal_IPs,
                "Quarantine_Period": self.quarantine_periods,
                "Polling_IP": self.myIP,
                "Destination_IPs": to_send_IPs
            }
            return to_send_IPs, message
        return to_send_IPs, {}

    def compute_next_to_send_Ips(self, mba_message):
        # Given that an MBA message is received, this function computes IPs of nodes that the MBA should be forwarded to
        # Next to Send IPs = 1 hop neighbors that are not malicious and are not in Destination IPs or Polling_IP
        to_send_IPs = list(set(self.neigh_IPs) - set(self.mal_IPs.values()) - set(self.blacklisted_IPs) - set(mba_message["Destination_IPs"]) - {mba_message["Polling_IP"]})
        return to_send_IPs

    def compute_mba_message_to_forward(self, mba_message, to_send_IPs):
        # Given that an MBA message is received, this function computes the MBA message that should be forwarded
        # by adding to_send_IPs in Destination_IPs of the original MBA message
        forward_mba_message = mba_message # Initializing with original message
        forward_mba_message["Destination_IPs"].extend(to_send_IPs)
        return forward_mba_message

    def send_mba_message(self, mba_message, to_send_IPs):
        for ip in to_send_IPs:
            # TODO: Remove in actual code
            destination_IP = 'localhost'
            destination_ID = ip.split('.')[-1] + 'a'
            port = ports_polling_request_MBA[destination_ID]

            # Sending mba message to node
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    if self.debug:
                        print("Sending mba message for mal nodes: {} to node {} from node {}".format(mba_message["Malicious_IP"], destination_ID, self.myID))
                    sock.connect((destination_IP, port))
                    sock.sendall(bytes(self.myID, 'utf-8'))
                    data = sock.recv(4096)

                    # Send encrypt and authenticated message using corresponding secret key
                    sock.sendall(pri.encrypt_response(bytes(json.dumps(mba_message), 'utf-8'), secrets[self.myID][destination_ID]))
                except ConnectionRefusedError:
                    if self.debug:
                        print("Connection refused by node " + destination_ID)
