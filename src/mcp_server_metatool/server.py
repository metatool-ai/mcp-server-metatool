from mcp import ClientSession, StdioServerParameters
from mcp.server.stdio import stdio_server
from mcp.client.stdio import stdio_client
from mcp.server.models import InitializationOptions

from mcp import types
from mcp.server import Server, NotificationOptions
import httpx
import os
import re
import sys
from contextlib import AsyncExitStack

exit_stacks = {}
sessions = {}

# Environment variables to inherit by default
DEFAULT_INHERITED_ENV_VARS = (
    [
        "APPDATA",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PATH",
        "PROCESSOR_ARCHITECTURE",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "USERNAME",
        "USERPROFILE",
    ]
    if sys.platform == "win32"
    else ["HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER"]
)


def get_default_environment() -> dict[str, str]:
    """
    Returns a default environment object including only environment variables deemed
    safe to inherit.
    """
    env: dict[str, str] = {}

    for key in DEFAULT_INHERITED_ENV_VARS:
        value = os.environ.get(key)
        if value is None:
            continue

        if value.startswith("()"):
            # Skip functions, which are a security risk
            continue

        env[key] = value

    return env


def sanitize_name(name: str) -> str:
    """Sanitize the name to only contain allowed characters."""
    return re.sub(r"[^a-zA-Z0-9_-]", "", name)


# Create and run the proxy server with the list of sessions
server = Server("mcp-server-metatool")


METATOOL_API_BASE_URL = os.environ.get(
    "METATOOL_API_BASE_URL", "http://localhost:12005"
)


async def get_mcp_servers() -> dict[str, StdioServerParameters]:
    try:
        async with httpx.AsyncClient() as client:
            """Get MCP servers from the API."""
            headers = {"Authorization": f"Bearer {os.environ['METATOOL_API_KEY']}"}
            response = await client.get(
                f"{METATOOL_API_BASE_URL}/api/mcp-servers", headers=headers
            )
            response.raise_for_status()
            data = response.json()
            server_dict = {}
            for params in data:
                # Convert empty lists and dicts to None
                if "args" in params and not params["args"]:
                    params["args"] = None

                # Merge environment variables
                params["env"] = {
                    **get_default_environment(),
                    **(params.get("env") or {}),
                }

                server_params = StdioServerParameters(**params)
                uuid = params.get("uuid")
                if uuid:
                    server_dict[uuid] = server_params
            return server_dict
    except Exception:
        return {}


async def initialize_session(session: ClientSession) -> dict:
    """Initialize a session and return its data."""
    initialize_result = await session.initialize()
    return {
        "session": session,
        "capabilities": initialize_result.capabilities,
        "name": initialize_result.serverInfo.name,
    }


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    # Reload MCP servers
    remote_server_params = await get_mcp_servers()

    all_tools = []

    # Process each server parameter
    for uuid, params in remote_server_params.items():
        if uuid not in exit_stacks:
            exit_stacks[uuid] = AsyncExitStack()
            stdio_transport = await exit_stacks[uuid].enter_async_context(
                stdio_client(params)
            )
            stdio, write = stdio_transport
            session = await exit_stacks[uuid].enter_async_context(
                ClientSession(stdio, write)
            )
            session_data = await initialize_session(session)
            sessions[uuid] = session_data
            if session_data["capabilities"].tools:
                response = await session_data["session"].list_tools()
                for tool in response.tools:
                    tool_copy = tool.model_copy()
                    tool_copy.name = (
                        f"{sanitize_name(session_data['name'])}__{tool.name}"
                    )
                    all_tools.append(tool_copy)
        else:
            session = sessions[uuid]["session"]
            session_data = sessions[uuid]
            if session_data["capabilities"].tools:
                response = await session.list_tools()
                for tool in response.tools:
                    tool_copy = tool.model_copy()
                    tool_copy.name = (
                        f"{sanitize_name(session_data['name'])}__{tool.name}"
                    )
                    all_tools.append(tool_copy)

    return all_tools


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    try:
        # Split the prefixed name into server name and tool name
        try:
            server_name, tool_name = name.split("__", 1)
        except ValueError:
            raise ValueError(
                f"Invalid tool name format: {name}. Expected format: server_name__tool_name"
            )

        # Get all server parameters
        remote_server_params = await get_mcp_servers()

        # Find the matching server parameters
        for uuid, params in remote_server_params.items():
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    session_data = await initialize_session(session)
                    if sanitize_name(session_data["name"]) == server_name:
                        result = await session.call_tool(
                            tool_name,
                            (arguments or {}),
                        )
                        return result.content

        raise ValueError(f"Server '{server_name}' not found")

    except Exception as e:
        return [types.TextContent(type="text", text=str(e))]


async def serve():
    # Run the server using stdin/stdout streams
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="metatool",
                server_version="0.0.4",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )
