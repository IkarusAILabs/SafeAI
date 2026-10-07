"""MCP server exposing resources and delegating tool calls to handlers."""
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server


def read_resource_handler(uri: str) -> str:
    """Handle resource read requests."""
    if uri.startswith("file://"):
        path = uri[7:]  # Remove file:// prefix
        try:
            with open(path) as f:
                return f.read()
        except FileNotFoundError:
            return f"File not found: {path}"
    return f"Unsupported URI: {uri}"


def write_resource_handler(uri: str, content: str) -> None:
    """Handle resource write requests."""
    if uri.startswith("file://"):
        path = uri[7:]  # Remove file:// prefix
        with open(path, 'w') as f:
            f.write(content)


def calculate_tool_handler(arguments: dict) -> str:
    """Handle calculation tool requests."""
    expression = arguments.get("expression", "")
    try:
        # Simple safe evaluation for demo
        result = eval(expression, {"__builtins__": {}}, {})
        return str(result)
    except Exception as e:
        return f"Calculation error: {str(e)}"


# Create MCP server
server = Server("demo-server")

# Register resource handlers
@server.read_resource()
async def handle_read_resource(uri: str) -> str:
    return read_resource_handler(uri)

@server.write_resource()  
async def handle_write_resource(uri: str, content: str) -> None:
    return write_resource_handler(uri)

# Register tool handlers
@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> str:
    if name == "calculate":
        return calculate_tool_handler(arguments)
    return f"Unknown tool: {name}"

# Server initialization options
server.init(
    InitializationOptions(
        server_name="demo-server",
        server_version="0.1.0"
    )
)