from header import *
import pandas as pd
import threading
import time
import decision_engine
import random
import mba
import polling.polling_requester as polling_requester
import quarantine.quarantine as quarantine
import node
import os

def sec_beat(myID, node):
    # This will be replaced by only_CA()
    sectable = pd.read_csv(f'{test_folder}dev_{myID}.csv')

    #sectable = only_ca(myID)
    sectable.drop_duplicates(inplace=True)

    #time.sleep(random.uniform(0, 1))
    time.sleep(int(myID[0]))
    if sectable.empty:
        print("Empty security table")
        print("Nothing to do")
    else:
        # Nodes that failed current secbeat's CA
        fail_IDs = sectable[sectable['CA_Result'] == 2]['ID'].to_list()
        # Nodes in fail_IDs for which polling request has not been received yet
        sus_IDs = []
        for ID in fail_IDs:
            if ID not in node.poll_requests_secbeat:
                sus_IDs.append(ID)

        # If there are failed nodes for which polling request has not been received yet
        if sus_IDs:
            print('************************************************************************')
            print('Conducting polling at node ', myID)
            print('sus_IDS: ', sus_IDs)
            print('fail_IDS: ', fail_IDs)
            print('node.poll_requests_secbeat: ', node.poll_requests_secbeat)
            # Create polling_requester object
            poll_requester = polling_requester.polling_requester(ID=myID, sus_IDs=sus_IDs, fail_IDs=fail_IDs)
            votes_df = poll_requester.conduct_polling()
            print('************************************************************************')

            result = decision_engine.decision_engine(votes_df)
            print("Result: ", result)
            # mal_IDs = IDs for which result is 194
            mal_IDs = [key for key, val in result.items() if val == 194]
            print('mal_IDs:', mal_IDs)

            #mal_IPs = list(set(sectable[sectable['ID'].isin(mal_IDs)]['IP'].to_list())) # TODO: get this from node object's mal_IDs attribute?
            # Initialize empty dictionaries
            mal_IPs = {}
            quarantine_periods = {}
            # If there are malicious nodes, broadcast MBA to neighbors that are not malicious
            for mal_ID in mal_IDs:
                # Mapping IDs to IPs
                # TODO: fix in actual code
                # TODO: run in parallel?
                mal_IP = sectable[sectable['ID'] == mal_ID]['IP'].values[0]
                quarantine_period = 30  # TODO: make it dependent on no of failures?

                mal_IPs[mal_ID] = mal_IP
                quarantine_periods[mal_ID] = quarantine_period

                # Block malicious node
                qua = quarantine.Quarantine(mal_id=mal_ID, mal_ip=mal_IP,quarantine_period=quarantine_period,blacklist_lock=node.lock_blacklist, blacklist_dir=node.blacklist_dir, blacklist_filename=node.blacklist_filename) # TODO: In actual implementation, remove taking blacklist_filename as argument. This is only done to test for multiple nodes in the same device
                qua.block()

            # Get list of currently blacklisted nodes
            with node.lock_blacklist:
                df = pd.read_csv(os.path.join(node.blacklist_dir, node.blacklist_filename))
            blacklisted_IPs = df['IP'].unique().tolist()
            # Call mba
            mba_obj = mba.MBA(myID=node.ID, myIP=node.IP, mal_IDs=mal_IDs, mal_IPs=mal_IPs,blacklisted_IPs=blacklisted_IPs, neigh_IPs=neigh_IPs[myID], quarantine_periods=quarantine_periods)
            to_send_IPs, mba_message = mba_obj.create_mba_message()
            # If there are nodes in to_send_IPs to whom MBA should be sent
            if to_send_IPs:
                mba_obj.send_mba_message(mba_message=mba_message, to_send_IPs=to_send_IPs)

def start_sec_beat(myID, myIP):
    # Initialize node and start socket to listen for any MBA/ Polling request
    node_object = node.node(myID, myIP)

    sec_beat(myID, node_object)

threads = []
for i in range(1, 8):
    thread = threading.Thread(target=start_sec_beat, args=(str(i)+'a', '10.10.10.'+str(i)), daemon=False)
    threads.append(thread)
    thread.start()

