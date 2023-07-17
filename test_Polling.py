from Polling import node
import pandas as pd
import json

class Test_Polling:
    def setup_method(self):
        self.ID = '1a'
        self.node_1 = node(ID=self.ID, test=True)

    def generate_polling_response_with_vote(self):
        sus_IDs = ['test2', 'test3']
        polling_ID = ['test4']
        vote = {
            'ID': ['test2', 'test3'],
            'CA_Result': [2, 2],
            'CA_Server': [self.ID, self.ID]
        }
        expected_message = json.dumps({
            "Subject": "Polling Response",
            "Suspected_ID": ['test2', 'test3'],
            "Polling_ID": ['test4'],
            "Vote": {
                'ID': ['test2', 'test3'],
                'CA_Result': [2, 2],
                'CA_Server': [self.ID, self.ID]
            },
            "Respondent_ID": self.ID
        })

        assert self.node_1.generate_polling_response(sus_IDs, polling_ID, vote) == expected_message

    def test_generate_polling_ack(self):
        sus_IDs = ['test2', 'test3']
        polling_ID = ['test4']
        expected_message = json.dumps({
            "Subject": "Polling ACK",
            "Suspected_ID": ['test2', 'test3'],
            "Polling_ID": ['test4'],
            "Respondent_ID": self.ID
        })

        assert self.node_1.generate_polling_ack(sus_IDs, polling_ID) == expected_message

    def test_dummy(self):
        polling_request = json.loads(self.node_1.generate_polling_request(sus_IDs=[1,2]))


