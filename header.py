import primitives as pri

# For test only
ports_polling_request_MBA = {'1': 5001, '2': 5002, '3': 5003, '4': 5004, '5': 5005, '6': 5006, '7': 5007}
ports_vote_collection = {'1': 6001, '2': 6002, '3': 6003, '4': 6004, '5': 6005, '6': 6006, '7': 6007}
secrets = {
    '1': {'2': pri.secret_1_2, '3': pri.secret_1_3, '4': pri.secret_1_4, '5': pri.secret_1_5, '6': pri.secret_1_6},
    '2': {'1': pri.secret_1_2, '3': pri.secret_2_3, '4': pri.secret_2_4, '5': pri.secret_2_5, '6': pri.secret_2_6},
    '3': {'1': pri.secret_1_3, '2': pri.secret_2_3, '4': pri.secret_3_4, '5': pri.secret_3_5},
    '4': {'1': pri.secret_1_4, '2': pri.secret_2_4, '3': pri.secret_3_4, '5': pri.secret_4_5},
    '5': {'1': pri.secret_1_5, '2': pri.secret_2_5, '3': pri.secret_3_5, '4': pri.secret_4_5},
    '6': {'1': pri.secret_1_6, '2': pri.secret_2_6},
    '7': {'4': pri.secret_4_7}
}

neighbors = {
    '1': ['2', '3', '4', '5', '6'],
    '2': ['1', '3', '4', '5', '6'],
    '3': ['1', '2', '4', '5'],
    '4': ['1', '2', '3', '5', '7'],
    '5': ['1', '2', '3', '4'],
    '6': ['1', '2'],
    '7': ['4']
}
