import pytest
import os
import json
from pysec_scanner.rl_agent import RLAgent

# This is needed to ensure that the rl_agent module can be found if tests are run directly
# using `pytest tests/test_rl_agent.py` from the root project directory.
import sys
project_root_rl = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if project_root_rl not in sys.path:
    sys.path.insert(0, project_root_rl)


# Step 2: Basic Fixture for RLAgent
@pytest.fixture
def agent():
    """Fixture to create an RLAgent instance for testing."""
    return RLAgent(alpha=0.1, gamma=0.9, epsilon=0.1) # Using specified params for consistency

# Step 3: Tests for get_state
def test_get_state_id(agent):
    assert agent.get_state('user_id', '123') == 'param_is_id'
    assert agent.get_state('sessionid', 'abc') == 'param_is_id' # Test variation

def test_get_state_search(agent):
    assert agent.get_state('query', 'test') == 'param_is_search'
    assert agent.get_state('keyword', 'search term') == 'param_is_search' # Test variation

def test_get_state_userinput(agent):
    assert agent.get_state('username', 'test') == 'param_is_userinput'
    assert agent.get_state('email', 'user@example.com') == 'param_is_userinput' # Test variation

def test_get_state_file(agent):
    assert agent.get_state('filepath', 'doc.txt') == 'param_is_file'
    assert agent.get_state('document_path', '/etc/passwd') == 'param_is_file' # Test variation

def test_get_state_url(agent):
    assert agent.get_state('redirectUrl', 'http://ex.com') == 'param_is_url'
    assert agent.get_state('next_page', '/index.html') == 'param_is_url' # Test variation

def test_get_state_numeric(agent):
    assert agent.get_state('count', '123') == 'param_is_numeric'
    # This case tests priority: 'id' in name should take precedence over value being numeric
    assert agent.get_state('item_id_count', '456') == 'param_is_id'

def test_get_state_alpha(agent):
    # This will be 'param_is_userinput' because 'name' is in the userinput keywords
    assert agent.get_state('name', 'test') == 'param_is_userinput' 
    # Test a param name not in keywords to ensure 'param_is_alpha' is reachable
    assert agent.get_state('somefield', 'onlyletters') == 'param_is_alpha'

def test_get_state_alnum(agent):
    assert agent.get_state('code', 'test1') == 'param_is_alnum'
     # Test a param name not in keywords to ensure 'param_is_alnum' is reachable
    assert agent.get_state('anotherfield', 'lettersAnd123') == 'param_is_alnum'

def test_get_state_other(agent):
    assert agent.get_state('unknown_param', 'some_value_!@#') == 'param_is_other'
    assert agent.get_state('complex', 'value with spaces and symbols !@#$%^&*()_+') == 'param_is_other'


# Step 4: Tests for choose_action
def test_choose_action_valid_action_returned(agent):
    state = "param_is_id"
    action = agent.choose_action(state)
    assert action in agent.actions

def test_choose_action_exploitation(agent):
    agent.epsilon = 0.0  # Force exploitation
    state = "param_is_id"
    
    # Scenario 1: run_sqli is better
    agent.q_table[state] = {"run_sqli": 0.5, "run_xss": 0.1}
    assert agent.choose_action(state) == "run_sqli"
    
    # Scenario 2: run_xss is better
    agent.q_table[state] = {"run_sqli": 0.1, "run_xss": 0.5}
    assert agent.choose_action(state) == "run_xss"

    # Scenario 3: New state, all actions Q value 0, should pick one (e.g., first one)
    # The default setdefault in choose_action handles this.
    # max() on dict with equal values typically returns the first one encountered.
    # This behavior can be a bit implementation-dependent for ties if not explicitly handled,
    # but for this test, as long as it's a valid action, it's okay.
    new_state = "param_is_new_for_exploitation"
    action = agent.choose_action(new_state)
    assert action in agent.actions 
    assert agent.q_table[new_state]["run_sqli"] == 0.0
    assert agent.q_table[new_state]["run_xss"] == 0.0


def test_choose_action_exploration(agent):
    agent.epsilon = 1.0  # Force exploration
    state = "param_is_id"
    # Run a few times and see if both actions appear
    # This test is probabilistic but with enough runs, it should cover actions.
    actions_chosen = {agent.choose_action(state) for _ in range(50)} # Increased range for higher probability
    
    # Check that at least one action was chosen, and all chosen actions are valid
    assert len(actions_chosen) > 0 
    assert all(a in agent.actions for a in actions_chosen)
    # For this specific case with 2 actions, if N is large enough, we expect both.
    if len(agent.actions) > 1: # Only assert if there's more than one action to choose from
         assert len(actions_chosen) == len(agent.actions) # Expects all actions to be chosen eventually


# Step 5: Tests for update_q_table
def test_update_q_table_new_state_action(agent):
    state, action, reward = "new_state_update", "run_sqli", 1.0
    # Q-table is initially empty for this state and action
    
    agent.update_q_table(state, action, reward)
    
    # Expected Q-value calculation: Q_old + alpha * (reward - Q_old)
    # Q_old for new_state_update, run_sqli is 0.0
    expected_q = 0.0 + agent.alpha * (reward - 0.0)
    assert agent.q_table[state][action] == pytest.approx(expected_q)

def test_update_q_table_existing_state_action(agent):
    state, action, reward = "existing_state_update", "run_xss", 1.0
    initial_q = 0.5
    
    # Pre-populate Q-table for this state and action
    agent.q_table[state] = {action: initial_q, "run_sqli": 0.2} # Add other actions too
    
    agent.update_q_table(state, action, reward)
    
    expected_q = initial_q + agent.alpha * (reward - initial_q)
    assert agent.q_table[state][action] == pytest.approx(expected_q)
    # Ensure other action for the state is not affected if not updated
    assert agent.q_table[state]["run_sqli"] == pytest.approx(0.2)


# Step 6: Tests for save_q_table and load_q_table
def test_save_load_q_table(agent, tmp_path):
    q_table_file = tmp_path / "test_q_table.json"
    
    state1, action1, reward1 = "test_state1", "run_sqli", 1.0
    state2, action2, reward2 = "test_state2", "run_xss", 0.8
    
    agent.update_q_table(state1, action1, reward1)
    agent.update_q_table(state2, action2, reward2)
    
    original_q_table = agent.q_table.copy() # Get a copy of the Q-table
    
    agent.save_q_table(str(q_table_file))
    assert os.path.exists(q_table_file)
    
    # Verify content of the saved file (optional but good for debugging)
    with open(q_table_file, 'r') as f:
        saved_data = json.load(f)
    assert saved_data == original_q_table

    new_agent = RLAgent(alpha=agent.alpha, gamma=agent.gamma, epsilon=agent.epsilon)
    new_agent.load_q_table(str(q_table_file))
    
    assert new_agent.q_table == original_q_table

def test_load_q_table_file_not_found(agent, capsys): # capsys to check print output
    # Ensure current agent's q_table is not empty for a good test, then clear it for new_agent
    agent.q_table = {"some_state": {"run_sqli": 1.0}} 
    
    new_agent = RLAgent() # Create a fresh agent
    new_agent.load_q_table("non_existent_file.json")
    
    assert new_agent.q_table == {} # Should be empty as per implementation
    captured = capsys.readouterr()
    assert "Q-table file non_existent_file.json not found" in captured.out


def test_load_q_table_invalid_json(agent, tmp_path, capsys):
    invalid_json_file = tmp_path / "invalid_q_table.json"
    with open(invalid_json_file, 'w') as f:
        f.write("{'invalid_json': ") # Malformed JSON
        
    new_agent = RLAgent()
    new_agent.load_q_table(str(invalid_json_file))
    
    assert new_agent.q_table == {}
    captured = capsys.readouterr()
    assert "Error decoding JSON" in captured.out

if __name__ == '__main__':
    pytest.main()
