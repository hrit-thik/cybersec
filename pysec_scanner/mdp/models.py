from enum import Enum, auto

class SecurityState(Enum):
    """
    Represents the possible security states of an asset or the system.
    """
    UNKNOWN = auto()                # Initial state before any scan
    NO_THREAT_DETECTED = auto()     # After a scan, no issues found
    LOW_THREAT_DETECTED = auto()    # E.g., informational findings, minor misconfigurations
    MEDIUM_THREAT_DETECTED = auto() # E.g., missing CSRF token, less severe XSS
    HIGH_THREAT_DETECTED = auto()   # E.g., SQLi, significant XSS
    CRITICAL_THREAT_DETECTED = auto() # E.g., severe, easily exploitable remote code execution
    UNDER_ATTACK = auto()           # Optional: Actively being exploited
    COMPROMISED = auto()            # Optional: Confirmed breach or unauthorized access


class ScannerAction(Enum):
    """
    Represents actions the scanner or a security agent can take.
    """
    INITIATE_SCAN = auto()          # Start a new scan
    INVESTIGATE_THREAT = auto()     # Deeper analysis of a potential threat
    REPORT_THREAT = auto()          # Inform user or system about a threat
    IGNORE_THREAT = auto()          # Acknowledge but take no action (e.g., false positive, accepted risk)
    REQUEST_PATCH = auto()          # Initiate remediation process
    VERIFY_PATCH = auto()           # Check if a patch was successfully applied
    NO_ACTION = auto()              # Explicitly do nothing


class RewardStructure:
    """
    Defines the rewards or costs associated with states and actions.
    These are conceptual and would be tuned for a specific MDP model.
    """
    def __init__(self):
        self.rewards = {
            # State-based rewards/costs
            SecurityState.UNKNOWN: -1, # Cost for uncertainty
            SecurityState.NO_THREAT_DETECTED: 10,
            SecurityState.LOW_THREAT_DETECTED: -5,
            SecurityState.MEDIUM_THREAT_DETECTED: -20,
            SecurityState.HIGH_THREAT_DETECTED: -100,
            SecurityState.CRITICAL_THREAT_DETECTED: -500,
            SecurityState.UNDER_ATTACK: -1000,
            SecurityState.COMPROMISED: -5000,

            # Action-based costs (rewards for beneficial actions could also be added)
            ScannerAction.INITIATE_SCAN: -2,        # Cost of performing a scan
            ScannerAction.INVESTIGATE_THREAT: -5,   # Cost of deeper investigation
            ScannerAction.REPORT_THREAT: -1,        # Minor cost for reporting
            ScannerAction.IGNORE_THREAT: 0,         # Neutral, but state cost remains
            ScannerAction.REQUEST_PATCH: -10,       # Cost/effort of patching
            ScannerAction.VERIFY_PATCH: -3,         # Cost of verifying a patch
            ScannerAction.NO_ACTION: 0,
        }

    def get_reward(self, state_or_action) -> int:
        """
        Returns the reward or cost associated with a given state or action.
        """
        return self.rewards.get(state_or_action, 0) # Default to 0 if not explicitly defined


class MDPAgent:
    """
    A very basic stub for an MDP-based security agent.
    """
    def __init__(self, reward_structure: RewardStructure = None):
        self.reward_structure = reward_structure if reward_structure else RewardStructure()
        # In a real MDP agent, you'd also have:
        # self.states = list(SecurityState)
        # self.actions = list(ScannerAction)
        # self.transition_model = {} # P(s' | s, a)
        # self.policy = {}           # pi(s) -> a
        # self.value_function = {}   # V(s) or Q(s,a)

    def choose_action(self, current_state: SecurityState) -> ScannerAction:
        """
        Placeholder for the logic to choose the best action based on the current state.
        In a real MDP, this would involve using the learned policy.
        """
        print(f"MDPAgent.choose_action called with state: {current_state}.")
        print("Policy not yet implemented. This would involve complex calculations.")

        # Example simple heuristic (not MDP optimal policy):
        if current_state in [SecurityState.HIGH_THREAT_DETECTED, SecurityState.CRITICAL_THREAT_DETECTED]:
            print("Heuristic: High/Critical threat detected, suggesting REQUEST_PATCH.")
            return ScannerAction.REQUEST_PATCH
        elif current_state in [SecurityState.LOW_THREAT_DETECTED, SecurityState.MEDIUM_THREAT_DETECTED]:
            print("Heuristic: Medium/Low threat detected, suggesting REPORT_THREAT.")
            return ScannerAction.REPORT_THREAT
        elif current_state == SecurityState.NO_THREAT_DETECTED:
            print("Heuristic: No threat detected, suggesting NO_ACTION.")
            return ScannerAction.NO_ACTION
        else: # UNKNOWN, etc.
            print("Heuristic: Defaulting to INITIATE_SCAN for unknown or other states.")
            return ScannerAction.INITIATE_SCAN

# Example Usage
if __name__ == '__main__':
    print("--- Demonstrating SecurityState Enum ---")
    for state in SecurityState:
        print(f"{state.name}: {state.value}")
    print(f"Accessing a specific state: {SecurityState.HIGH_THREAT_DETECTED}")

    print("\n--- Demonstrating ScannerAction Enum ---")
    for action in ScannerAction:
        print(f"{action.name}: {action.value}")
    print(f"Accessing a specific action: {ScannerAction.INITIATE_SCAN}")

    print("\n--- Demonstrating RewardStructure ---")
    rewards = RewardStructure()
    print(f"Reward for NO_THREAT_DETECTED: {rewards.get_reward(SecurityState.NO_THREAT_DETECTED)}")
    print(f"Cost for INITIATE_SCAN: {rewards.get_reward(ScannerAction.INITIATE_SCAN)}")
    print(f"Reward for an undefined state (defaults to 0): {rewards.get_reward('NON_EXISTENT_STATE')}")

    # Modifying a reward (example)
    rewards.rewards[SecurityState.NO_THREAT_DETECTED] = 15 
    print(f"Modified reward for NO_THREAT_DETECTED: {rewards.get_reward(SecurityState.NO_THREAT_DETECTED)}")


    print("\n--- Demonstrating MDPAgent (Stub) ---")
    agent = MDPAgent(rewards)

    test_states = [
        SecurityState.UNKNOWN,
        SecurityState.NO_THREAT_DETECTED,
        SecurityState.MEDIUM_THREAT_DETECTED,
        SecurityState.HIGH_THREAT_DETECTED,
    ]

    for state in test_states:
        chosen_action = agent.choose_action(state)
        print(f"  For state {state.name}, agent chose action: {chosen_action.name}")
        print(f"  Associated reward/cost for this action: {agent.reward_structure.get_reward(chosen_action)}")
        print("-" * 20)

    print("\nMDP Model Stubs Defined.")
