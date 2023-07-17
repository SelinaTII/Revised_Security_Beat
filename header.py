import primitives as pri

testcase = 3

ips = {'1a': '10.10.10.1',
       '2a': '10.10.10.2',
       '3a': '10.10.10.3',
       '4a': '10.10.10.4',
       '5a': '10.10.10.5',
       '6a': '10.10.10.6',
       '7a': '10.10.10.7'}

if testcase == 1:
    # 1 node is rogue (node 5a)
    test_folder = 'test_inputs/testcase_1/'
    dummy = b'\xe7U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x61\x8e)%\xacN\xd9\xd8\x8d\xe8x14\x00' # dummy secret for rogue node
    # For test only
    ports_polling_request_MBA = {'1a': 5001, '2a': 5002, '3a': 5003, '4a': 5004, '5a': 5005, '6a': 5006, '7a': 5007}
    ports_vote_collection = {'1a': 6001, '2a': 6002, '3a': 6003, '4a': 6004, '5a': 6005, '6a': 6006, '7a': 6007}
    secrets = {
        '1a': {'2a': pri.secret_1_2, '3a': pri.secret_1_3, '4a': pri.secret_1_4, '5a': pri.secret_1_5, '6a': pri.secret_1_6},
        '2a': {'1a': pri.secret_1_2, '3a': pri.secret_2_3, '4a': pri.secret_2_4, '5a': pri.secret_2_5, '6a': pri.secret_2_6},
        '3a': {'1a': pri.secret_1_3, '2a': pri.secret_2_3, '4a': pri.secret_3_4, '5a': pri.secret_3_5},
        '4a': {'1a': pri.secret_1_4, '2a': pri.secret_2_4, '3a': pri.secret_3_4, '5a': pri.secret_4_5, '7a': pri.secret_4_7},
        #'5a': {'1a': pri.secret_1_5, '2a': pri.secret_2_5, '3a': pri.secret_3_5, '4a': pri.secret_4_5},
        '5a': {'1a': dummy, '2a': dummy, '3a': dummy, '4a': dummy},
        '6a': {'1a': pri.secret_1_6, '2a': pri.secret_2_6},
        '7a': {'4a': pri.secret_4_7}
    }

    neighbors = {
        '1a': ['2a', '3a', '4a', '5a', '6a'],
        '2a': ['1a', '3a', '4a', '5a', '6a'],
        '3a': ['1a', '2a', '4a', '5a'],
        '4a': ['1a', '2a', '3a', '5a', '7a'],
        '5a': ['1a', '2a', '3a', '4a'],
        '6a': ['1a', '2a'],
        '7a': ['4a']
    }


elif testcase == 2:
    # 2 nodes are rogue (nodes 4a, 5a)
    test_folder = 'test_inputs/testcase_2/'
    dummy = b'\xe7U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x61\x8e)%\xacN\xd9\xd8\x8d\xe8x14\x00'  # dummy secret for rogue node
    # For test only
    ports_polling_request_MBA = {'1a': 5001, '2a': 5002, '3a': 5003, '4a': 5004, '5a': 5005, '6a': 5006, '7a': 5007}
    ports_vote_collection = {'1a': 6001, '2a': 6002, '3a': 6003, '4a': 6004, '5a': 6005, '6a': 6006, '7a': 6007}
    secrets = {
        '1a': {'2a': pri.secret_1_2, '3a': pri.secret_1_3, '4a': pri.secret_1_4, '5a': pri.secret_1_5, '6a': pri.secret_1_6},
        '2a': {'1a': pri.secret_1_2, '3a': pri.secret_2_3, '4a': pri.secret_2_4, '5a': pri.secret_2_5, '6a': pri.secret_2_6},
        '3a': {'1a': pri.secret_1_3, '2a': pri.secret_2_3, '4a': pri.secret_3_4, '5a': pri.secret_3_5},
        #'4a': {'1a': pri.secret_1_4, '2a': pri.secret_2_4, '3a': pri.secret_3_4, '5a': pri.secret_4_5, '7a': pri.secret_4_7},
        '4a': {'1a': dummy, '2a': dummy, '3a': dummy, '5a': dummy, '7a': dummy},
        # '5a': {'1a': pri.secret_1_5, '2a': pri.secret_2_5, '3a': pri.secret_3_5, '4a': pri.secret_4_5},
        '5a': {'1a': dummy, '2a': dummy, '3a': dummy, '4a': dummy},
        '6a': {'1a': pri.secret_1_6, '2a': pri.secret_2_6},
        '7a': {'4a': pri.secret_4_7}
    }

    neighbors = {
        '1a': ['2a', '3a', '4a', '5a', '6a'],
        '2a': ['1a', '3a', '4a', '5a', '6a'],
        '3a': ['1a', '2a', '4a', '5a'],
        '4a': ['1a', '2a', '3a', '5a', '7a'],
        '5a': ['1a', '2a', '3a', '4a'],
        '6a': ['1a', '2a'],
        '7a': ['4a']
    }

elif testcase == 3:
    # 2 nodes are rogue (nodes 5a, 6a)
    test_folder = 'test_inputs/testcase_3/'
    dummy = b'\xe7U\xce\x06 nNU\xd1Q\xdfxx\xf0\x0f\xc1b\x8c\x61\x8e)%\xacN\xd9\xd8\x8d\xe8x14\x00'  # dummy secret for rogue node
    # For test only
    ports_polling_request_MBA = {'1a': 5001, '2a': 5002, '3a': 5003, '4a': 5004, '5a': 5005, '6a': 5006, '7a': 5007}
    ports_vote_collection = {'1a': 6001, '2a': 6002, '3a': 6003, '4a': 6004, '5a': 6005, '6a': 6006, '7a': 6007}
    secrets = {
        '1a': {'2a': pri.secret_1_2, '3a': pri.secret_1_3, '4a': pri.secret_1_4, '5a': pri.secret_1_5, '6a': pri.secret_1_6},
        '2a': {'1a': pri.secret_1_2, '3a': pri.secret_2_3, '4a': pri.secret_2_4, '5a': pri.secret_2_5, '6a': pri.secret_2_6},
        '3a': {'1a': pri.secret_1_3, '2a': pri.secret_2_3, '4a': pri.secret_3_4, '5a': pri.secret_3_5},
        '4a': {'1a': pri.secret_1_4, '2a': pri.secret_2_4, '3a': pri.secret_3_4, '5a': pri.secret_4_5, '7a': pri.secret_4_7},
        # '5a': {'1a': pri.secret_1_5, '2a': pri.secret_2_5, '3a': pri.secret_3_5, '4a': pri.secret_4_5},
        '5a': {'1a': dummy, '2a': dummy, '3a': dummy, '4a': dummy},
        #'6a': {'1a': pri.secret_1_6, '2a': pri.secret_2_6},
        '6a': {'1a': dummy, '2a': dummy},
        '7a': {'4a': pri.secret_4_7}
    }

    neighbors = {
        '1a': ['2a', '3a', '4a', '5a', '6a'],
        '2a': ['1a', '3a', '4a', '5a', '6a'],
        '3a': ['1a', '2a', '4a', '5a'],
        '4a': ['1a', '2a', '3a', '5a', '7a'],
        '5a': ['1a', '2a', '3a', '4a'],
        '6a': ['1a', '2a'],
        '7a': ['4a']
    }


neigh_IPs = {}
for key in neighbors.keys():
    neigh_IPs[key] = []
    for neigh in neighbors[key]:
        neigh_IPs[key].append(ips[neigh])