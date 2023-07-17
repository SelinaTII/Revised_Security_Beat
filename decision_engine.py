# Run decision engine for given entries in dataframe
def decision_engine(votes_df):
    result = {}
    # for unique suspected nodes present in votes_df
    for node in votes_df['ID'].unique():
        # TODO add consistency checks
        malicious_vote_count = votes_df[(votes_df['ID'] == node) & (votes_df['CA_Result'] == 2)].shape[0]
        total_vote_count = votes_df[votes_df['ID'] == node].shape[0]
        if malicious_vote_count == total_vote_count or malicious_vote_count >= total_vote_count / 2:
            result[node] = 194  # malicious
        else:
            result[node] = 65  # benign
    return result


