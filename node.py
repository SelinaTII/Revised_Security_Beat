import queue
from header import *
import primitives as pri
import funsocket as fs
import decision_engine
import polling.polling_responder as polling_responder
import polling.polling_requester as polling_requester
import mba


import socket
import threading
import contextlib
import cryptography.exceptions
import time
import json
import pandas as pd
import numpy as np
from queue import Queue
import multiprocessing

# TODO: check if daemon should be true or false in actual code
class node:
    # TODO: in actual code: remove sending node ID in socket connections, remove use of separate ports for different nodes -> should be IPs
    def __init__(self, ID, IP, debug=False, test=False):
        self.ID = ID
        self.IP = IP
        self.CA_complete = False
        self.debug = debug
        self.poll_requests_secbeat = [] # Nodes for which poll requests have been received in current secbeat
        self.lock_polling_request = threading.Lock()
        if not test:
            server_thread = threading.Thread(target=self.poll_mba_server, args=(), daemon=False)
            server_thread.start()

    def poll_mba_server(self):
        # Listen for any MBA/ Polling request
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print("Starting voting server at node ", self.ID)
            sock.bind(('localhost', ports_polling_request_MBA[self.ID]))
            sock.listen()
            while 1:
                conn, addr = sock.accept()
                voter_client_thread = threading.Thread(target=self.handle_request, args=(conn, addr), daemon=False)
                voter_client_thread.start()

    def handle_request(self, conn, addr):
        # Handles MBA/ Polling request received
        # Checks if received message is a polling request or MBA, then calls appropriate methods

        # Receive sender's ID (only for test to identify sender as localhost is being used for everyone)
        data = conn.recv(4096)
        conn.sendall(data)
        sending_node = data.decode()

        # Receive encrypted and authenticated message
        data = conn.recv(4096)
        try:
            # Decrypt and authenticate message with corresponding secret key
            message = pri.decrypt_response(data, secrets[self.ID][sending_node]).decode()

            # Convert received json to dict
            message_dict = json.loads(message)

            # Checks if received message is a polling request or MBA, then call appropriate functions
            if message_dict["Subject"] == 'Polling Request':
                if self.debug:
                    print("Received polling request at node " + self.ID + " from node " + sending_node)
                    # print(f"Connection established from {addr[0]}:{addr[1]}")
                    print("Received message: {}".format(message_dict))
                # Append sus_ID to polling_requests_secbeat
                with self.lock_polling_request:
                    self.poll_requests_secbeat.extend(message_dict["Suspected_ID"])
                    #print('self.poll_requests_secbeat: ', self.poll_requests_secbeat)
                # Create polling_responder object
                poll_responder = polling_responder.polling_responder(ID=self.ID, sus_IDs=message_dict["Suspected_ID"], polling_ID=message_dict["Polling_ID"])
                # Respond to poll
                poll_responder.respond_to_poll()

            elif message_dict["Subject"] == 'MBA':
                if self.debug:
                    print("Received MBA message at node " + self.ID + " from node " + sending_node)
                    print("Received message: {}".format(message_dict))
                # TODO: check if MBA for malicious node has already been received and forwarded in current secbeat
                # Create MBA object
                mba_receiver = mba.MBA(myID=self.ID, myIP=self.IP, mal_IPs=message_dict["Malicious_IPs"],neigh_IPs=neigh_IPs[self.ID], quarantine_period=message_dict["Quarantine_Period"])
                to_send_IPs = mba_receiver.compute_next_to_send_Ips(mba_message=message_dict)
                # If there are nodes in to_send_IPs to whom MBA should be forwarded
                if to_send_IPs:
                    forward_mba_message = mba_receiver.compute_mba_message_to_forward(mba_message=message_dict, to_send_IPs=to_send_IPs)
                    # send forward_mba_message to to_send_IPs
                    mba_receiver.send_mba_message(mba_message=forward_mba_message, to_send_IPs=to_send_IPs)

        except cryptography.exceptions.InvalidTag:
            if self.debug:
                print("Received message decryption and authentication failed")

def sample_run():
    node_1 = node('1a', '10.10.10.1')
    node_2 = node('2a', '10.10.10.2', debug=True)
    node_3 = node('3a', '10.10.10.3')
    node_4 = node('4a', '10.10.10.4')
    node_5 = node('5a', '10.10.10.5')
    node_6 = node('6a', '10.10.10.6')
    node_7 = node('7a', '10.10.10.7')

    polling_id = '3a'
    poll_requester = polling_requester.polling_requester(ID=polling_id, sus_IDs=['5a'], fail_IDs=['5a'])
    votes_df = poll_requester.conduct_polling()
    result = decision_engine.decision_engine(votes_df)
    print("Result: ", result)
    sectable = pd.read_csv(f'{test_folder}dev_1a.csv')
    mal_IDs = [key for key, val in result.items() if val == 194]
    if mal_IDs:
        # Mapping IDs to IPs
        # TODO: fix in actual code
        mal_IPs = list(set(sectable[sectable['ID'].isin(mal_IDs)]['IP'].to_list()))
        mal_IPs.sort()
        print('mal_IPs:', mal_IPs)

        # Initialize mba object
        mba_obj = mba.MBA(myID=polling_id, myIP=ips[polling_id], mal_IPs=mal_IPs,
                          neigh_IPs=neigh_IPs[polling_id])
        to_send_IPs, mba_message = mba_obj.create_mba_message()
        print(mba_message)
        print(type(mba_message))
        print(json.dumps(mba_message))
        # If there are nodes in to_send_IPs to whom MBA should be sent
        if to_send_IPs:
            mba_obj.send_mba_message(mba_message=mba_message, to_send_IPs=to_send_IPs)

#sample_run()