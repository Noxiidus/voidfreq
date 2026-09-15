from setuptools import setup, find_packages

setup(
    name="voidfreq",
    version="0.2.0",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "netifaces>=0.11.0",
        "mac-vendor-lookup>=0.1.12",
        "python-nmap>=0.7.1",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "voidfreq=voidfreq.cli:main",
        ],
    },
    python_requires=">=3.11",
    author="Noxiidus",
    description="WiFi Red/Blue Team Framework",
    url="https://github.com/Noxiidus/voidfreq",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
)
