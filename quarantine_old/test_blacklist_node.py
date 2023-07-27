from blacklist_node import *

class Test_blacklist_node:
    # Test the blacklist_node function
    def setup_method(self): 
        # Define test data
        self.test_directory_name = '../auth'
        self.test_file_name = 'blacklist.csv'
        self.test_file_path = os.path.join(self.test_directory_name, self.test_file_name)
        
        self.test_node_IDs = ['1a', '2a', '3a']
        self.test_node_IPs = ['10.10.10.1', '10.10.10.2', '10.10.10.3']
        self.test_quarantine_periods = [20, 20, 20]
        self.lock = threading.Lock()

    # Clean up after testing
    def teardown_method(self):
        if os.path.exists(self.test_file_path):
            os.remove(self.test_file_path)
        if os.path.exists(self.test_directory_name):
            os.rmdir(self.test_directory_name)
    
    def test_blacklist_node_if_file_is_created(self):
        # Test case 1 - File does not exist, check if file is created
        blacklist_node(self.test_node_IDs, self.test_node_IPs, self.test_quarantine_periods, self.lock)
        assert os.path.exists(os.path.join(self.test_directory_name, self.test_file_name))
    
    def test_blacklist_node_if_data_is_added(self):
        # Test case 2 - File does not exist, check if data is added to file
        blacklist_node(self.test_node_IDs, self.test_node_IPs, self.test_quarantine_periods, self.lock)
        no_of_rows_added = 3
        df_from_file = pd.read_csv(self.test_file_path)
        assert len(df_from_file) == no_of_rows_added
    
    def test_blacklist_node_appending_data_to_existing_file(self):
        # Test case 3 - File exists with 3 rows, check if new data is appended to the file
        # Creates file with 3 rows
        blacklist_node(self.test_node_IDs, self.test_node_IPs, self.test_quarantine_periods, self.lock)
        no_of_existing_rows = 3
        # Additional data (2 rows)
        additional_node_IDs = ['4a', '5a']
        additional_IPs = ['10.10.10.4', '10.10.10.5']
        additional_periods = [20, 20]
        no_of_rows_added = 2
    
        blacklist_node(additional_node_IDs, additional_IPs, additional_periods, self.lock)
        df_from_file = pd.read_csv(self.test_file_path)
        assert len(df_from_file) == no_of_existing_rows + no_of_rows_added

    def test_blacklist_node_new_data_for_node_already_in_file(self):
        # Test case 3 - File exists with 3 rows, new data is added for a node already present in the file
        # New data has a later quarantine end time, so it should replace the old entry for the node
        # Creates file with 3 rows
        blacklist_node(self.test_node_IDs, self.test_node_IPs, self.test_quarantine_periods, self.lock)

        # Additional data (2 rows)
        additional_node_IDs = ['1a']
        additional_IPs = ['10.10.10.1']
        additional_periods = [30]

        blacklist_node(additional_node_IDs, additional_IPs, additional_periods, self.lock)
        df_from_file = pd.read_csv(self.test_file_path)

        expected_quarantine_period = 30 # From newly added data
        assert len(df_from_file[df_from_file['ID']=='1a']) == 1 # To check that old entry was replaced
        assert df_from_file.loc[df_from_file['ID'] == '1a', 'Quarantine_Period'].values[0] == expected_quarantine_period

    def test_blacklist_node_stale_data_for_node_already_in_file(self):
        # Test case 3 - File exists with 3 rows, data is added for a node already present in the file
        # Added data has a earlier quarantine end time, so it is stale and should not replace the old entry for the node
        # Creates file with 3 rows
        blacklist_node(self.test_node_IDs, self.test_node_IPs, self.test_quarantine_periods, self.lock)

        # Additional data (2 rows)
        additional_node_IDs = ['1a']
        additional_IPs = ['10.10.10.1']
        additional_periods = [10]

        blacklist_node(additional_node_IDs, additional_IPs, additional_periods, self.lock)
        df_from_file = pd.read_csv(self.test_file_path)

        expected_quarantine_period = 20  # From existing data
        assert len(df_from_file[df_from_file['ID'] == '1a']) == 1 # To check that new row has not been added
        assert df_from_file.loc[df_from_file['ID'] == '1a', 'Quarantine_Period'].values[0] == expected_quarantine_period # To check that entry is the existing entry (not newly added one)