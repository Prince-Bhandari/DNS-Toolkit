from setuptools import setup, find_packages
setup(
    name="dns-toolkit",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "dnspython>=2.4.0",
        "python-whois>=0.8.0",
        "validators>=0.22.0",
        "requests>=2.31.0",
        "tldextract>=5.1.0",
        "rich>=13.7.0",
        "click>=8.1.0",
        "aiohttp>=3.9.0",
        "aiodns>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "dns-toolkit=dns_toolkit.cli:main",
        ],
    },
    python_requires=">=3.9",
)
