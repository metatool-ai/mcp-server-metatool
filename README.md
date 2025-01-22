# My Package

## Overview
Metatool MCP Server

## Installation
Best way to use this is through uv
A METATOOL_API_KEY environment variable must be set
```bash
export METATOOL_API_KEY="my_api_key" # get from metatool-ai/metatool-app
uvx mcp-server-metatool
```

You need a MCP Client to connect to this server to use it.

## Additional Configuration
A METATOOL_API_BASE_URL environment variable can be set to point to another metatool instance

```bash
export METATOOL_API_BASE_URL="http://localhost:12005"
```

## License
Apache License 2.0