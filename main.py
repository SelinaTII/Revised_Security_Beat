from header import *
import Polling

def sec_beat(myID, node):
    # This will be replaced by only_CA()
    sectable = pd.read_csv(f'test_inputs/dev_{myID}.csv')
    #sectable = only_ca(myID)
    sectable.drop_duplicates(inplace=True)
    if sectable.empty:
        print("Empty security table")
        print("Nothing to do")
    else:
        # Nodes that failed current secbeat's CA
        fail_IDs = sectable[sectable['CA_Result'] == 2]['ID'].to_list()
        # Nodes in fail_IDs for which polling request has not been received yet
        sus_IDs = fail_IDs
        for ID in sus_IDs:
            if ID in node.poll_requests_secbeat:
                sus_IDs.remove(ID)

        # If there are failed nodes for which polling request has not been received yet
        if sus_IDs:
            node.conduct_polling(sus_IDs)


    ut.exchage_table(sectable, start_server_thread)
    global_table = pd.read_csv('auth/global_table.csv')
    if global_table.empty:
        print("Empty Global security table")
        print("Nothing to do")
    else:
        ness_result, mapp = decision_engine(global_table, ma, q)
        #quaran(ness_result, q, sectable, ma, mapp)
        quaran(ness_result, q, global_table, ma, mapp)


def start_sec_beat(myID):
    # Initialize node and start socket to listen for any MBA/ Polling request
    node = Polling.node(myID)

    sec_beat(myID, node)

