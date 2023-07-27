import os
import time
import pandas as pd
import threading

def blacklist_node(node_IDs, node_IPs, quaratine_periods, lock, debug=False):
    # node_IDs: list of IDs of nodes that should be put to quarantine
    # node_IPs: list of IPs of nodes that should be put to quarantine
    # quarantine_periods: list of quarantine periods for each node
    # Function enters IDs, IPs and quarantine period and start timestamps for each node into auth/blacklist.csv file

    dir_path = '../auth'
    file_name = 'blacklist.csv'
    file_path = os.path.join(dir_path, file_name)

    # Create the directory if it doesn't exist
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

    # Initialize df with function arguments
    data = {'ID': node_IDs, 'IP': node_IPs, 'Quarantine_Period': quaratine_periods}
    df = pd.DataFrame(data)
    # Add current timestamp as start timestamp for each row in df
    df['Start_timestamp'] = time.time()
    df['End_timestamp'] = df['Start_timestamp'] + df['Quarantine_Period']

    df.sort_values(by=['ID', 'IP', 'End_timestamp'], inplace=True)
    df.drop_duplicates(subset=['ID', 'IP'], keep='last', inplace=True)
    if debug:
        print('df to add:\n{}'.format(df))
    # Append data to the CSV file
    # If the file doesn't exist, write the header row (if required)
    if not os.path.isfile(file_path):
        with lock:
            df.to_csv(file_path, index=False, header=True)
    else:
        with lock:
            existing_df = pd.read_csv(file_path)
        if debug:
            print('existing df:\n{}'.format(existing_df))
        new_df = existing_df.append(df, ignore_index=True)
        if debug:
            print('df after append:\n{}'.format(new_df))
        # Replace duplicate entries for a node by the entry with latest quarantine end time
        new_df.sort_values(by=['ID', 'IP', 'End_timestamp'], inplace=True)
        if debug:
            print('df after sorting:\n{}'.format(new_df))
        new_df.drop_duplicates(subset=['ID', 'IP'], keep='last', inplace=True)
        if debug:
            print('df after dropping duplicates:\n{}'.format(new_df))
        with lock:
            new_df.to_csv(file_path, index=False, header=True, mode='w')

