from autogen import AssistantAgent, GroupChat, GroupChatManager

coder = AssistantAgent(name="coder", llm_config=False)
tester = AssistantAgent(name="tester", llm_config=False)
chat = GroupChat(agents=[coder, tester], messages=[], max_round=6)
manager = GroupChatManager(groupchat=chat, name="lead", llm_config=False)
