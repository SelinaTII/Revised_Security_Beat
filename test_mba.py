from mba import MBA
import pytest
class Test_mba:
    def test_create_mba_message(self):
        # Test for mba.create_mba_message() for when there are nodes to send the mba to
        mba = MBA(
            myID='1',
            myIP='10.10.10.1',
            mal_IDs=['2', '3'],
            mal_IPs={'2': '10.10.10.2', '3': '10.10.10.3'},
            blacklisted_IPs=[],
            neigh_IPs=['10.10.10.2', '10.10.10.3', '10.10.10.4', '10.10.10.5'],
            quarantine_periods={'2': 20, '3': 30}
        )
        to_send_IPs, mba_message = mba.create_mba_message()

        expected_to_send_IPs = ['10.10.10.4', '10.10.10.5']
        expected_mba_message = {
            "Subject": "MBA",
            "Malicious_ID": ['2', '3'],
            "Malicious_IP": {'2': '10.10.10.2', '3': '10.10.10.3'},
            "Quarantine_Period": {'2': 20, '3': 30},
            "Polling_IP": '10.10.10.1',
            "Destination_IPs": ['10.10.10.4', '10.10.10.5']
        }

        assert to_send_IPs == expected_to_send_IPs
        assert mba_message == expected_mba_message

    def test_create_mba_message_for_noIPstosend(self):
        # Test for mba.create_mba_message() for when there are no nodes to send the mba to
        mba = MBA(
            myID='1',
            myIP='10.10.10.1',
            mal_IDs=['2'],
            mal_IPs={'2': '10.10.10.2'},
            blacklisted_IPs=['10.10.10.3'],
            neigh_IPs=['10.10.10.2', '10.10.10.3'],
            quarantine_periods={'2': 20}
        )
        to_send_IPs, mba_message = mba.create_mba_message()

        expected_to_send_IPs = []
        expected_mba_message = {}

        assert to_send_IPs == expected_to_send_IPs
        assert mba_message == expected_mba_message

    def test_compute_next_to_send_IPs(self):
        # Test for mba.compute_next_to_send_Ips() for when there is next IPs to send
        mba_message = {
            "Subject": "MBA",
            "Malicious_ID": ['2'],
            "Malicious_IP": {'2': '10.10.10.2'},
            "Quarantine_Period": {'2': 20},
            "Polling_IP": '10.10.10.1',
            "Destination_IPs": ['10.10.10.4', '10.10.10.5']
        }
        mba = MBA(
            myID='4',
            myIP='10.10.10.4',
            mal_IDs = mba_message["Malicious_ID"],
            mal_IPs=mba_message["Malicious_IP"],
            blacklisted_IPs=['10.10.10.3'],
            neigh_IPs=['10.10.10.1', '10.10.10.2', '10.10.10.3', '10.10.10.4', '10.10.10.5', '10.10.10.6', '10.10.10.7'],
            quarantine_periods=mba_message["Quarantine_Period"]
        )
        # The function should return 1 hop neighbors that are not malicious or blacklisted and are not in Destination IPs or Polling_IP
        expected_next_to_send_IPs = ['10.10.10.6', '10.10.10.7']
        assert set(mba.compute_next_to_send_Ips(mba_message)) == set(expected_next_to_send_IPs)

    def test_compute_next_to_send_Ips_for_noIPtosend(self):
        # Test for mba.compute_next_to_send_Ips() for when there is no next IP to send
        mba_message = {
            "Subject": "MBA",
            "Malicious_ID": ['2'],
            "Malicious_IP": {'2': '10.10.10.2'},
            "Quarantine_Period": {'2': 20},
            "Polling_IP": '10.10.10.1',
            "Destination_IPs": ['10.10.10.4', '10.10.10.5']
        }
        mba = MBA(
            myID='4',
            myIP='10.10.10.4',
            mal_IDs=mba_message["Malicious_ID"],
            mal_IPs=mba_message["Malicious_IP"],
            blacklisted_IPs=['10.10.10.3'],
            neigh_IPs=['10.10.10.1', '10.10.10.2', '10.10.10.3', '10.10.10.4', '10.10.10.5'],
            quarantine_periods=mba_message["Quarantine_Period"]
        )
        # The function should return 1 hop neighbors that are not malicious and are not in Destination IPs or Polling_IP
        assert mba.compute_next_to_send_Ips(mba_message) == []

    def test_compute_mba_to_forward(self):
        # Test for mba.compute_mba_to_forward()
        mba_message = {
            "Subject": "MBA",
            "Malicious_ID": ['2', '3'],
            "Malicious_IP": {'2': '10.10.10.2', '3': '10.10.10.3'},
            "Quarantine_Period": {'2': 20, '3': 30},
            "Polling_IP": '10.10.10.1',
            "Destination_IPs": ['10.10.10.4', '10.10.10.5']
        }
        to_send_IPs = ['10.10.10.6', '10.10.10.7']
        mba = MBA(
            myID='4',
            myIP='10.10.10.4',
            mal_IDs=mba_message["Malicious_ID"],
            mal_IPs=mba_message["Malicious_IP"],
            blacklisted_IPs=[],
            neigh_IPs=['10.10.10.1', '10.10.10.2', '10.10.10.3', '10.10.10.4', '10.10.10.5', '10.10.10.6', '10.10.10.7'],
            quarantine_periods=mba_message["Quarantine_Period"]
        )
        # The function should append IPs in to_send_IPs to Destination_IPs
        expected_forward_mba_message = {
            "Subject": "MBA",
            "Malicious_ID": ['2', '3'],
            "Malicious_IP": {'2': '10.10.10.2', '3': '10.10.10.3'},
            "Quarantine_Period": {'2': 20, '3': 30},
            "Polling_IP": '10.10.10.1',
            "Destination_IPs": ['10.10.10.4', '10.10.10.5', '10.10.10.6', '10.10.10.7']
        }
        assert mba.compute_mba_message_to_forward(mba_message, to_send_IPs) == expected_forward_mba_message
