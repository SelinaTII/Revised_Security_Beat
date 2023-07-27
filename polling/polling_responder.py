from header import *
import primitives as pri
import socket
import json
import pandas as pd

# TODO: check if daemon should be true or false in actual code

class polling_responder:
    def __init__(self, ID, sus_IDs, polling_ID, debug=False, test=False):
        self.ID = ID
        self.sus_IDs = sus_IDs
        self.polling_ID = polling_ID
        self.CA_complete = False
        self.debug = debug

    def respond_to_poll(self):
        # Generate and send polling response
        sectable = pd.read_csv(f'{test_folder}dev_{self.ID}.csv')

        # Check if one or more sus_IDs is in my security table
        if sectable['ID'].isin(self.sus_IDs).any():
            # If true, send table entry for sus_IDs as vote
            vote = sectable[sectable['ID'].isin(self.sus_IDs)].to_dict()
            response_message = self.generate_polling_response_with_vote(vote)
        else:
            # send polling acknowledgement
            response_message = self.generate_polling_ack()
        self.send_message(response_message)

    def generate_polling_response_with_vote(self, vote):
        # Generate polling response for given suspected node
        # might need to add IP as well
        message_dict = {
            "Subject": "Polling Response",
            "Suspected_ID": self.sus_IDs,
            "Polling_ID": self.polling_ID,
            "Vote": vote,
            "Respondent_ID": self.ID
        }
        # convert dict to json
        message = json.dumps(message_dict)
        return message

    def generate_polling_ack(self):
        # Generate polling ack for given suspected node in case the node is not a neighbor
        # might need to add IP as well
        message_dict = {
            "Subject": "Polling ACK",
            "Suspected_ID": self.sus_IDs,
            "Polling_ID": self.polling_ID,
            "Respondent_ID": self.ID
        }
        # convert dict to json
        message = json.dumps(message_dict)
        return message

    def send_message(self, message):
        destination_ID = self.polling_ID
        destination_IP = 'localhost'
        port = ports_vote_collection[self.polling_ID]
        # Sending poll response to polling node
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                if self.debug:
                    print("Sending message to node " + destination_ID + " from node " + self.ID)
                sock.connect((destination_IP, port))
                sock.sendall(bytes(self.ID, 'utf-8'))
                data = sock.recv(4096)

                # Send encrypt and authenticated message using corresponding secret key
                sock.sendall(pri.encrypt_response(bytes(message, 'utf-8'), secrets[self.ID][destination_ID]))
            except ConnectionRefusedError:
                if self.debug:
                    print("Connection refused by node " + destination_ID)

