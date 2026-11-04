from langgraph.prebuilt import create_react_agent
from langgraph_swarm import create_handoff_tool, create_swarm


def book_flight(destination: str) -> str:
    return destination


def book_hotel(city: str) -> str:
    return city


flights = create_react_agent(
    "m", tools=[book_flight, create_handoff_tool(agent_name="hotels")], name="flights")
hotels = create_react_agent(
    "m", tools=[book_hotel, create_handoff_tool(agent_name="flights"),
                create_handoff_tool(agent_name="cars")], name="hotels")
app = create_swarm([flights, hotels], default_active_agent="flights").compile()
