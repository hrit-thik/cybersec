import json
import random

class RLAgent:
    def __init__(self, alpha=0.1, gamma=0.9, epsilon=0.1):
        """
        Initializes the Reinforcement Learning Agent.

        Args:
            alpha (float): Learning rate.
            gamma (float): Discount factor.
            epsilon (float): Exploration rate.
        """
        self.q_table = {}  # Q-table: state -> {action: q_value}
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon
        # Define actions the agent can take for a given parameter
        # These correspond to specific detector types in the scanner
        self.actions = ["run_sqli", "run_xss"] # Add more actions as detectors are available
                                               # e.g., "run_csrf_check", "run_idor_check"
                                               # For now, focusing on parameter-specific tests
    
    def get_state(self, param_name, param_value):
        """
        Determines a simplified state based on parameter name and value characteristics.
        """
        param_name_lower = str(param_name).lower() # Ensure param_name is string and lowercase
        str_param_value = str(param_value) # Ensure param_value is string for checks

        # Order of checks is important: more specific name checks first
        if 'id' in param_name_lower:
            return "param_is_id"
        if param_name_lower in ['q', 'query', 'search', 'keyword', 'term']: # Added 'term'
            return "param_is_search"
        if param_name_lower in ['name', 'user', 'usr', 'login', 'email', 'username', 'pass', 'password']: # Added 'pass', 'password'
            return "param_is_userinput"
        if param_name_lower in ['file', 'path', 'document', 'folder', 'dir', 'filename']: # Added 'dir', 'filename'
            return "param_is_file"
        if param_name_lower in ['url', 'uri', 'link', 'redirect', 'next', 'goto', 'page', 'return', 'ref']: # Added 'page', 'return', 'ref'
            return "param_is_url"
        
        # Value-based checks if no specific name pattern matched
        if str_param_value.isnumeric():
            return "param_is_numeric"
        if str_param_value.isalpha():
            return "param_is_alpha"
        if str_param_value.isalnum(): # Checks if all chars are alphanumeric
            return "param_is_alnum"
        
        # Default state if none of the above
        return "param_is_other"

    def choose_action(self, state):
        """
        Chooses an action based on the current state using an epsilon-greedy strategy.
        """
        if random.uniform(0, 1) < self.epsilon:
            # Exploration: choose a random action
            return random.choice(self.actions)
        else:
            # Exploitation: choose the best action from Q-table
            # Initialize Q-values for the current state if not already present
            self.q_table.setdefault(state, {action: 0.0 for action in self.actions})
            
            q_values = self.q_table[state]
            # Return the action with the maximum Q-value.
            # If all Q-values are 0 or there's a tie, max() will pick one.
            # (e.g. the first one it encounters among those with max value)
            return max(q_values, key=q_values.get)

    def update_q_table(self, state, action, reward):
        """
        Updates the Q-value for a given state-action pair using a simplified Q-learning rule.
        """
        # Ensure the state exists in the Q-table, and the action exists for that state.
        self.q_table.setdefault(state, {act: 0.0 for act in self.actions})
        self.q_table[state].setdefault(action, 0.0) # Should not be necessary if state initialized with all actions

        current_q = self.q_table[state][action]
        # Simplified Q-learning update (ignoring next state's max Q-value for simplicity here,
        # as the problem doesn't define a clear next_state from an action's result directly)
        new_q = current_q + self.alpha * (reward - current_q)
        self.q_table[state][action] = new_q

    def save_q_table(self, filename="q_table.json"):
        """
        Saves the Q-table to a JSON file.
        """
        try:
            with open(filename, 'w') as f:
                json.dump(self.q_table, f, indent=4)
            print(f"Q-table successfully saved to {filename}")
        except IOError as e:
            print(f"Error saving Q-table to {filename}: {e}")
        except Exception as e: # Catch any other unexpected errors
            print(f"An unexpected error occurred while saving Q-table: {e}")

    def load_q_table(self, filename="q_table.json"):
        """
        Loads the Q-table from a JSON file.
        If the file is not found or data is invalid, starts with an empty Q-table.
        """
        try:
            with open(filename, 'r') as f:
                self.q_table = json.load(f)
            print(f"Q-table successfully loaded from {filename}")
        except FileNotFoundError:
            print(f"Q-table file {filename} not found. Starting with an empty Q-table.")
            self.q_table = {} # Ensure it's reset if file not found
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from {filename}: {e}. Starting with an empty Q-table.")
            self.q_table = {}
        except Exception as e: # Catch any other unexpected errors
            print(f"An unexpected error occurred while loading Q-table: {e}. Starting with an empty Q-table.")
            self.q_table = {}
