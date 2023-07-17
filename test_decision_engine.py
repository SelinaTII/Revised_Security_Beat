import decision_engine
import pandas as pd

pass_result = 1
fail_result = 2
malicious = 194
benign = 65

class Test_decision_engine:
    def setup_method(self):
        self.sample_votes_df = pd.DataFrame({
            'ID': ['1_fail',
                   '2_fail', '2_fail',
                   '1_fail_1_pass', '1_fail_1_pass',
                   '2_fail_1_pass', '2_fail_1_pass', '2_fail_1_pass',
                   '2_fail_2_pass', '2_fail_2_pass', '2_fail_2_pass', '2_fail_2_pass',
                   '2_fail_3_pass', '2_fail_3_pass', '2_fail_3_pass', '2_fail_3_pass', '2_fail_3_pass'],
            'CA_Result': [fail_result,
                          fail_result, fail_result,
                          fail_result, pass_result,
                          fail_result, pass_result, fail_result,
                          pass_result, fail_result, pass_result, fail_result,
                          pass_result, fail_result, pass_result, fail_result, pass_result
                          ]
        })
        self.result = decision_engine.decision_engine(self.sample_votes_df)

    # Testing for node with 1 fail entry
    # Result should be malicious
    def test_1_fail(self):
        assert self.result['1_fail'] == malicious

    # Testing for node with 2 fail entries
    # Result should be malicious
    def test_2_fail(self):
        assert self.result['2_fail'] == malicious

    # Testing for node with 1 fail, 1 pass entries
    # Result should be malicious
    def test_1_fail_1_pass(self):
        assert self.result['1_fail_1_pass'] == malicious

    # Testing for node with majority fail entries
    # Result should be malicious
    def test_2_fail_1_pass(self):
        assert self.result['2_fail_1_pass'] == malicious

    # Testing for node with half fail entries
    # Result should be malicious
    def test_2_fail_2_pass(self):
        assert self.result['2_fail_2_pass'] == malicious

    # Testing for node with majority pass entries
    # Result should be benign
    def test_2_fail_3_pass(self):
        assert self.result['2_fail_3_pass'] == benign





