import time
import shutil
from quarantine import *


class Test_quarantine:
    # Test quarantine
    def setup_method(self):
        # Define test data
        self.test_directory_name = '../auth'
        self.test_file_name = 'blacklist.csv'
        self.test_file_path = os.path.join(self.test_directory_name, self.test_file_name)
        self.blacklist_lock = threading.Lock()

    # Clean up after testing
    def teardown_method(self):
        #if os.path.exists(self.test_file_path):
            #os.remove(self.test_file_path)
        if os.path.exists(self.test_directory_name):
            #os.rmdir(self.test_directory_name)
            shutil.rmtree(self.test_directory_name)

    def test_add_to_blacklist_if_file_is_created(self):
        # Test case 1 - File does not exist, check if file is created
        qua_1 = Quarantine(mal_id='1a', mal_ip='10.10.10.1', quarantine_period=15, blacklist_lock=self.blacklist_lock)
        qua_1.add_to_blacklist()
        no_of_rows_added = 1
        assert os.path.exists(os.path.join(self.test_directory_name, self.test_file_name))
        df_from_file = pd.read_csv(self.test_file_path)
        assert len(df_from_file) == no_of_rows_added

    def test_add_to_blacklist_if_data_is_appended(self):
        # Test case 2 - check if additional data is appended to file
        qua_1 = Quarantine(mal_id='1a', mal_ip='10.10.10.1', quarantine_period=15, blacklist_lock=self.blacklist_lock)
        qua_1.add_to_blacklist()
        qua_2 = Quarantine(mal_id='2a', mal_ip='10.10.10.2', quarantine_period=20, blacklist_lock=self.blacklist_lock)
        qua_2.add_to_blacklist()
        no_of_rows_added = 2
        df_from_file = pd.read_csv(self.test_file_path)
        assert len(df_from_file) == no_of_rows_added

    def test_remove_from_blacklist(self):
        # Test case - check if data is removed after calling remove_from_blacklist()
        qua_1 = Quarantine(mal_id='1a', mal_ip='10.10.10.1', quarantine_period=15, blacklist_lock=self.blacklist_lock)
        qua_1.add_to_blacklist()
        qua_2 = Quarantine(mal_id='2a', mal_ip='10.10.10.2', quarantine_period=20, blacklist_lock=self.blacklist_lock)
        qua_2.add_to_blacklist()
        no_of_rows_added = 2
        qua_1.remove_from_blacklist() # Removes 1a from blacklist
        no_of_rows_removed = 1
        df_from_file = pd.read_csv(self.test_file_path)
        assert len(df_from_file) == no_of_rows_added - no_of_rows_removed # Check if row has been removed
        assert (~df_from_file['ID'].isin(['1a'])).any() # Check that row for ID=1a is not present

    def test_block_if_unblock_is_called_after_quarantine(self):
        # Test case - check if data is removed after calling remove_from_blacklist()
        qua_1 = Quarantine(mal_id='1a', mal_ip='10.10.10.1', quarantine_period=2, blacklist_lock=self.blacklist_lock)
        qua_1.block()
        no_of_rows_added = 1
        df_from_file = pd.read_csv(self.test_file_path)
        assert len(df_from_file) == no_of_rows_added # check if row has been added
        time.sleep(2.5) # sleep till quarantine period is over
        no_of_rows_removed = 1 # Node should be removed from blacklist after end of quarantine period
        df_from_file = pd.read_csv(self.test_file_path)
        assert len(df_from_file) == no_of_rows_added - no_of_rows_removed # Check if row has been removed successfully



