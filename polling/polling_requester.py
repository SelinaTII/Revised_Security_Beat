import queue
from header import *
import primitives as pri
import socket
import threading
import cryptography.exceptions
import json
import pandas as pd
from queue import Queue

# TODO: check if daemon should be true or false in actual code

class polling_requester:
    def __init__(self, ID, sus_IDs, fail_IDs, debug=False, test=False):
        self.ID = ID
        self.sus_IDs = sus_IDs # sus_IDs: failed nodes for which polling request will be sent
        self.fail_IDs = fail_IDs # fail_IDs: nodes that failed current CA
        self.debug = debug
        self.votes_q = Queue()  # Queue to store votes received
        self.lock_polling_response = threading.Lock()

    def conduct_polling(self):

        lock_polling_request = threading.Lock()
        # nodes to poll: neighbors except failed nodes
        polling_requests = list(set(neighbors[self.ID]) - set(self.fail_IDs))
        # if sus_ID in polling_requests: polling_requests.remove(sus_ID)
        polling_request_threads = []
        polling_response_threads = []
        polling_respondents = []
        # Start server socket to collect votes
        polling_server_thread = threading.Thread(target=self.polling_server, args=(polling_response_threads, polling_respondents), daemon=False)
        polling_server_thread.start()

        # Start poll at polling node
        # Send polling request to all neighbors except failed nodes
        for neigh in list(set(neighbors[self.ID]) - set(self.fail_IDs)):
            polling_request_thread = threading.Thread(target=self.send_polling_request, args=(
                neigh, 'localhost', ports_polling_request_MBA[neigh], polling_requests,
                lock_polling_request), daemon=True)
            polling_request_thread.start()
            polling_request_threads.append(polling_request_thread)

        # Wait to collect polling responses from all nodes or until polling response server socket does not time out
        while polling_server_thread.is_alive(): # thread is alive until socket times out
            if set(polling_requests) == set(polling_respondents):
                # TODO: Terminate polling server thread if all polling responses are received
                break

        # Wait to handle all poll responses
        for thread in polling_request_threads + polling_response_threads:
            thread.join()

        # Initialize votes_df with own table entry for suspicious node
        sectable = pd.read_csv(f'{test_folder}dev_{self.ID}.csv')

        votes_df = sectable[sectable['ID'].isin(self.sus_IDs)]
        # pop all votes from votes_q and append them to votes_df
        while True:
            try:
                vote_df = self.votes_q.get(block=False)
                print(f"Popped item: ", vote_df)
                # TODO: verify that vote is in correct format: check for column names and datatype of each column, check if IDs are of sus_IDs?
                # verify that vote format matches format of security table
                if self.verify_vote_format(vote_df, sectable):
                    # Only take votes for IDs in sus_IDs (in case a node responds with a different table entry)
                    #TODO: remove later
                    vote_df = vote_df[vote_df['ID'].isin(self.sus_IDs)]
                    votes_df = pd.concat([votes_df, vote_df], ignore_index=True)
            except queue.Empty:
                break

        print("polling_requests: ", polling_requests)
        print("polling_respondents: ", polling_respondents)
        print("\nVotes:")
        print(votes_df)
        return votes_df

    def polling_server(self, polling_response_threads, polling_respondents):
        # Create socket to receive polling responses
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # TODO: confirm timeout time
            sock.settimeout(60)
            print("Starting voting server at node ", self.ID)
            sock.bind(('localhost', ports_vote_collection[self.ID]))
            sock.listen()
            # while stop flag has not been set
            while 1:
                try:
                    conn, addr = sock.accept()
                    polling_response_thread = threading.Thread(target=self.handle_polling_response, args=(conn, polling_respondents), daemon=False)
                    polling_response_thread.start()
                    polling_response_threads.append(polling_response_thread)
                except socket.timeout:
                    print("Polling response collection timed out")
                    break
            print('Checkpoint: exiting server thread')

    def generate_polling_request(self):
        # Generate polling request for given suspected node/s
        # sus_IDs is a list
        # might need to add IP as well
        message_dict = {
            "Subject": "Polling Request",
            "Suspected_ID": self.sus_IDs,
            "Polling_ID": self.ID
        }

        # convert dict to json
        message = json.dumps(message_dict)
        return message

    def send_polling_request(self, destination_ID, destination_IP, port, polling_requests, lock):
        # Send polling request to neighbor destination_ID node
        # If connection refused by node, remove it from list of nodes in polling_requests
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                print("Sending polling request to node " + destination_ID)
                sock.connect((destination_IP, port))
                # Send my ID (only for test)
                sock.sendall(bytes(self.ID, 'utf-8'))
                data = sock.recv(4096)
                # Send polling request
                message = bytes(self.generate_polling_request(), 'utf-8')
                # Send encrypt and authenticated message using corresponding secret key
                sock.sendall(pri.encrypt_response(message, secrets[self.ID][destination_ID]))
            except ConnectionRefusedError:
                print("Connection refused by node ", destination_ID)
                with lock:
                    polling_requests.remove(destination_ID)

    def handle_polling_response(self, conn, polling_respondents):
        # Function to handle polling response
        data = conn.recv(4096)
        conn.sendall(data)
        polling_respondent = data.decode()

        # Append node to list of polling respondents
        with self.lock_polling_response:
            polling_respondents.append(polling_respondent)

        data = conn.recv(4096)
        try:
            # Decrypt and authenticate message with corresponding secret key
            message = pri.decrypt_response(data, secrets[self.ID][polling_respondent]).decode()
            print("Polling response: ", message)

            # Convert received json to dict
            message_dict = json.loads(message)

            # If received message is a polling response with vote, put the received vote in votes_q
            if message_dict["Subject"] == 'Polling Response':
                vote = message_dict["Vote"]
                vote_df = pd.DataFrame.from_dict(vote)
                self.votes_q.put(vote_df)
        except cryptography.exceptions.InvalidTag:
            print("Received message decryption and authentication failed")

    def verify_vote_format(self, vote_df, mySectable):
        # Check if column names and column datatypes of vote dataframe matches the nodes's security table
        if (set(vote_df.columns) == set(mySectable.columns)) and all(vote_df.dtypes == mySectable.dtypes):
            return True
        return False