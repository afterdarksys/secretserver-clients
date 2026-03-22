from setuptools import setup, find_packages

setup(
    name="secretserver",
    version="1.2.0",
    description="SecretServer.io Python client library",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="AfterDark Systems",
    url="https://github.com/afterdarksys/secretserver-clients",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],  # zero external dependencies — stdlib only
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="secrets management vault api-key password",
)
