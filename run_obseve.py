# run_observe.py
import json
from core.observe import observe_node

if __name__ == "__main__":
    # Create an empty dummy state
    dummy_state = {"events": []}
    
    # Run just the observe node
    result = observe_node(dummy_state)
    
    # Print the real cluster data it found
    print("\n--- OBSERVED CLUSTER DATA ---")
    print(json.dumps(result, indent=2))