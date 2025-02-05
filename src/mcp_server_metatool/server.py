from mcp import ClientSession, StdioServerParameters
from mcp.server.stdio import stdio_server
from mcp.client.stdio import stdio_client
from mcp.server.models import InitializationOptions

from mcp import types
from mcp.server import Server, NotificationOptions
import httpx
import os
import re
import tempfile
import subprocess
import ast
import sys

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


async def get_mcp_servers() -> list[StdioServerParameters]:
    try:
        async with httpx.AsyncClient() as client:
            """Get MCP servers from the API."""
            headers = {"Authorization": f"Bearer {os.environ['METATOOL_API_KEY']}"}
            response = await client.get(
                f"{METATOOL_API_BASE_URL}/api/mcp-servers", headers=headers
            )
            response.raise_for_status()
            data = response.json()
            server_params = []
            for params in data:
                # Convert empty lists and dicts to None
                if "args" in params and not params["args"]:
                    params["args"] = None

                # Merge environment variables
                params["env"] = {
                    **get_default_environment(),
                    **(params.get("env") or {}),
                }

                server_params.append(StdioServerParameters(**params))
            return server_params
    except Exception:
        return []


def extract_imports(code: str) -> list[str]:
    """Extract top-level import statements from the Python code."""
    try:
        tree = ast.parse(code)
        imports = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])

        return list(imports)
    except Exception as e:
        raise RuntimeError(f"Error parsing imports: {e}") from e


def install_dependencies(dependencies: list[str]):
    """Install required dependencies using uv pip."""
    try:
        subprocess.run(["uv", "pip", "install"] + dependencies, check=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to install dependencies: {e}") from e


async def get_custom_mcp_servers() -> list[StdioServerParameters]:
    try:
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {os.environ['METATOOL_API_KEY']}"}
            response = await client.get(
                f"{METATOOL_API_BASE_URL}/api/custom-mcp-servers", headers=headers
            )
            response.raise_for_status()
            data = response.json()
            server_params = []

            for params in data:
                if "code" not in params or "code_uuid" not in params:
                    continue

                code_uuid = params["code_uuid"]

                # Create temp file for the script
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=f"_{code_uuid}.py", delete=False
                ) as temp_file:
                    temp_file.write(params["code"])
                    script_path = temp_file.name

                # Extract dependencies from the code
                try:
                    dependencies = extract_imports(params["code"])
                    if dependencies:
                        try:
                            install_dependencies(dependencies)
                        except Exception as e:
                            print(
                                f"Failed to install dependencies for server {code_uuid}: {e}"
                            )
                            continue
                except Exception as e:
                    print(f"Failed to extract imports for server {code_uuid}: {e}")
                    continue

                params["command"] = "uv"
                params["args"] = ["run", script_path] + params.get("additionalArgs", [])

                # Merge environment variables
                params["env"] = {
                    **get_default_environment(),
                    **(params.get("env") or {}),
                }

                server_params.append(StdioServerParameters(**params))
            return server_params
    except Exception as e:
        print(f"Error fetching MCP servers: {e}")
        return []


async def get_all_mcp_servers() -> list[StdioServerParameters]:
    server_params = await get_mcp_servers()
    custom_server_params = await get_custom_mcp_servers()
    return server_params + custom_server_params


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
    remote_server_params = await get_all_mcp_servers()

    # Combine with default servers
    all_server_params = remote_server_params
    all_tools = []

    # Process each server parameter
    for params in all_server_params:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                session_data = await initialize_session(session)
                if session_data["capabilities"].tools:
                    response = await session_data["session"].list_tools()
                    for tool in response.tools:
                        tool_copy = tool.copy()
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
        remote_server_params = await get_all_mcp_servers()

        # Find the matching server parameters
        for params in remote_server_params:
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
                server_version="0.0.1",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )
