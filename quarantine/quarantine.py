import os
import time
import pandas as pd
import threading

class Quarantine:
    # TODO: In actual implementation, remove taking blacklist_filename as argument. This is only done to test for multiple nodes in the same device
    def __init__(self, mal_id, mal_ip, quarantine_period, blacklist_lock, blacklist_dir = '../auth', blacklist_filename = 'blacklist.csv', debug=False):
        self.dir = blacklist_dir
        self.file_name = blacklist_filename
        self.file_path = os.path.join(self.dir, self.file_name)
        self.mal_id = mal_id
        self.mal_ip = mal_ip
        self.quarantine_period = quarantine_period
        self.blacklist_lock = blacklist_lock
        self.debug = debug
    def block(self):
        # Add node to blacklist and block node
        # Calls unblock method automatically once quarantine is over
        self.add_to_blacklist()
        # TODO: code to block malicious node
        print('Blocking node {}'.format(self.mal_id))
        # Start timer thread that calls unblock function once quarantine period is over
        quarantine_timer = threading.Timer(self.quarantine_period, self.unblock)
        quarantine_timer.start()

    def add_to_blacklist(self):
        # Add node to blacklist
        # Create the directory if it doesn't exist
        if not os.path.exists(self.dir):
            os.makedirs(self.dir)

        # Initialize df
        data = {'ID': [self.mal_id], 'IP': [self.mal_ip], 'Quarantine_Period': [self.quarantine_period]}
        df = pd.DataFrame(data)
        # Add current timestamp as start timestamp for each row in df
        df['Start_timestamp'] = time.time()
        df['End_timestamp'] = df['Start_timestamp'] + df['Quarantine_Period']
        if self.debug:
            print('df to add:\n{}'.format(df))
        # Append data to the CSV file
        # If the file doesn't exist, write the header row (if required)
        if not os.path.isfile(self.file_path):
            with self.blacklist_lock:
                df.to_csv(self.file_path, index=False, header=True)
        else:
            with self.blacklist_lock:
                df.to_csv(self.file_path, index=False, header=False, mode='a')

    def unblock(self):
        # Remove node from blacklist and unblock node
        self.remove_from_blacklist()
        # TODO: code to unblock malicious node
        print('Unblocking node {}'.format(self.mal_id))

    def remove_from_blacklist(self):
        # Remove node from blacklist
        with self.blacklist_lock:
            # Read the df from the CSV file
            df = pd.read_csv(self.file_path)
            # Remove row for malicious node
            df = df[df['ID'] != self.mal_id]
            if self.debug:
                print('df after removing mal node {}:\n{}'.format(self.mal_id, df))
            # Save the updated DataFrame back to the original CSV file
            df.to_csv(self.file_path, index=False, header=True, mode='w')



