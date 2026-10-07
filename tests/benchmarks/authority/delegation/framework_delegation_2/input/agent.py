"""AutoGen agent delegation with assistant agent and user proxy pattern."""
import autogen


# Define assistant agent
assistant = autogen.AssistantAgent(
    name="assistant",
    llm_config={"config_list": [{"model": "gpt-4"}]},
    system_message="You are a helpful AI assistant that can help with various tasks."
)

# Define user proxy agent that can execute code
user_proxy = autogen.UserProxyAgent(
    name="user_proxy",
    human_input_mode="NEVER",
    max_consecutive_auto_reply=10,
    code_execution_config={"work_dir": "coding", "use_docker": False},
)

# Register functions for the assistant
def analyze_data(data: str) -> str:
    """Analyze provided data and return insights."""
    return f"Analysis of {len(data)} characters: contains {data.count(' ')} words"

def process_file(filepath: str) -> str:
    """Process a file and return results.""" 
    with open(filepath, 'r') as f:
        return f"Processed: {f.read()[:100]}..."

assistant.register_for_execution(name="analyze_data")(analyze_data)
assistant.register_for_execution(name="process_file")(process_file)

# Initiate chat - delegation happens when assistant suggests code execution
# and user_proxy executes it