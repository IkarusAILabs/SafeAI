"""MCP client delegating to remote MCP server tools."""
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def delegate_to_mcp_server():
    """Delegate tool execution to MCP server."""
    server_params = StdioServerParameters(
        command="mcp-server-filesystem",
        args=["/path/to/allowed/directory"]
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the connection
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            
            # Call a tool on the MCP server (delegation)
            result = await session.call_tool("read_file", {"path": "/etc/passwd"})
            return result.content


# Tool wrapper for the MCP delegation
def mcp_delegate_tool(action: str, params: dict) -> str:
    """Tool interface for MCP delegation."""
    import asyncio
    return asyncio.run(delegate_to_mcp_server())