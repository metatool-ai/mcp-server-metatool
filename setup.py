from setuptools import setup, find_packages

setup(
    name="mcp-server-metatool",
    version="0.0.2",
    author="James Zhang",
    author_email="james@jczstudio.com",
    description="Metatool MCP Server",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    python_requires=">=3.10",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Programming Language :: Python :: 3.10",
    ],
    install_requires=["mcp", "requests"],
    extras_require={
        "dev": [
            "pytest",
            "twine",
            "wheel",
        ],
    },
)
