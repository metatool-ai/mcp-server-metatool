from mcp import ClientSession, StdioServerParameters
from mcp.server.stdio import stdio_server
from mcp.client.stdio import stdio_client

from mcp import types
from mcp.server import Server
import httpx
import os
import re
import sys
from contextlib import AsyncExitStack
import hashlib
import json

_sessions = {}

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


def compute_params_hash(params: StdioServerParameters, uuid: str) -> str:
    """Compute a hash of StdioServerParameters and UUID to detect changes."""
    # Convert params to a dictionary and sort keys for consistent hashing
    params_dict = {
        "uuid": uuid,
        "command": params.command,
        "args": params.args,
        "env": dict(sorted(params.env.items())) if params.env else None,
    }
    # Convert to JSON string with sorted keys for consistent hashing
    params_json = json.dumps(params_dict, sort_keys=True)
    # Compute SHA-256 hash
    return hashlib.sha256(params_json.encode()).hexdigest()


# Create and run the proxy server with the list of sessions
server = Server("mcp-server-metatool")


METATOOL_API_BASE_URL = os.environ.get(
    "METATOOL_API_BASE_URL", "http://localhost:12005"
)


_mcp_servers_cache: dict[str, StdioServerParameters] | None = None


async def get_mcp_servers(
    force_refresh: bool = False,
) -> dict[str, StdioServerParameters]:
    """Get MCP servers from the API with caching support."""
    global _mcp_servers_cache

    if not force_refresh and _mcp_servers_cache is not None:
        return _mcp_servers_cache

    try:
        async with httpx.AsyncClient() as client:
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

            _mcp_servers_cache = server_dict
            return server_dict
    except Exception:
        if _mcp_servers_cache is not None:
            return _mcp_servers_cache
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
    # Reload MCP servers with force refresh
    remote_server_params = await get_mcp_servers(force_refresh=True)

    all_tools = []

    # Process each server parameter
    for uuid, params in remote_server_params.items():
        # Compute hash of parameters
        params_hash = compute_params_hash(params, uuid)
        session_key = f"{uuid}_{params_hash}"

        if session_key not in _sessions:
            # Close existing session for this UUID if it exists with a different hash
            old_session_keys = [k for k in _sessions.keys() if k.startswith(f"{uuid}_")]
            for old_key in old_session_keys:
                await _sessions[old_key]["exit_stack"].aclose()
                del _sessions[old_key]

            _sessions[session_key] = {"exit_stack": AsyncExitStack()}
            stdio_transport = await _sessions[session_key][
                "exit_stack"
            ].enter_async_context(stdio_client(params))
            stdio, write = stdio_transport
            session = await _sessions[session_key]["exit_stack"].enter_async_context(
                ClientSession(stdio, write)
            )
            session_data = await initialize_session(session)
            _sessions[session_key].update(session_data)
            if session_data["capabilities"].tools:
                response = await session_data["session"].list_tools()
                for tool in response.tools:
                    tool_copy = tool.model_copy()
                    tool_copy.name = (
                        f"{sanitize_name(session_data['name'])}__{tool.name}"
                    )
                    all_tools.append(tool_copy)
        else:
            session = _sessions[session_key]["session"]
            session_data = _sessions[session_key]
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

        # Get all server parameters from cache
        remote_server_params = await get_mcp_servers(force_refresh=False)

        # Find the matching server parameters
        for uuid, params in remote_server_params.items():
            params_hash = compute_params_hash(params, uuid)
            session_key = f"{uuid}_{params_hash}"

            if session_key not in _sessions:
                continue

            session = _sessions[session_key]["session"]
            session_data = _sessions[session_key]

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
        options = server.create_initialization_options()
        try:
            await server.run(read_stream, write_stream, options, raise_exceptions=True)
        finally:
            for session_info in _sessions.values():
                if "exit_stack" in session_info:
                    await session_info["exit_stack"].aclose()
            _sessions.clear()
