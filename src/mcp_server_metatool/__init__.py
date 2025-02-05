"""
Metatool MCP Server
"""

__version__ = "0.0.4"

from .server import serve


def main():
    """MCP Server metatool - proxy to join multiple MCP servers"""
    import asyncio

    asyncio.run(serve())


if __name__ == "__main__":
    main()
