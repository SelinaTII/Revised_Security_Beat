from header import *
import Polling
import pandas as pd
import threading
import time
import decision_engine
import random
import mba
import polling.polling_requester as polling_requester
import node

def sec_beat(myID, node):
    # This will be replaced by only_CA()
    sectable = pd.read_csv(f'{test_folder}dev_{myID}.csv')

    #sectable = only_ca(myID)
    sectable.drop_duplicates(inplace=True)

    time.sleep(random.uniform(0, 1))
    #time.sleep(int(myID[0]))
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

            # If there are malicious nodes, broadcast MBA to neighbors that are not malicious
            if mal_IDs:
                # Mapping IDs to IPs
                # TODO: fix in actual code
                mal_IPs = list(set(sectable[sectable['ID'].isin(mal_IDs)]['IP'].to_list()))
                mal_IPs.sort()
                print('mal_IPs:', mal_IPs)

                # Initialize mba object
                mba_obj = mba.MBA(myID=node.ID, myIP=node.IP, mal_IPs=mal_IPs, neigh_IPs=neigh_IPs[myID])
                to_send_IPs, mba_message = mba_obj.create_mba_message()
                # If there are nodes in to_send_IPs to whom MBA should be sent
                if to_send_IPs:
                    mba_obj.send_mba_message(mba_message=mba_message, to_send_IPs=to_send_IPs)

    """
    ut.exchage_table(sectable, start_server_thread)
    global_table = pd.read_csv('auth/global_table.csv')
    if global_table.empty:
        print("Empty Global security table")
        print("Nothing to do")
    else:
        ness_result, mapp = decision_engine(global_table, ma, q)
        #quaran(ness_result, q, sectable, ma, mapp)
        quaran(ness_result, q, global_table, ma, mapp)
    """

def start_sec_beat(myID, myIP):
    # Initialize node and start socket to listen for any MBA/ Polling request
    node_object = node.node(myID, myIP)

    sec_beat(myID, node_object)

threads = []
for i in range(1, 8):
    thread = threading.Thread(target=start_sec_beat, args=(str(i)+'a', '10.10.10.'+str(i)), daemon=False)
    threads.append(thread)
    thread.start()

