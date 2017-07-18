from setuptools import setup, find_packages

# defines __version__
exec(open("trustme/_version.py").read())

setup(
    name="trustme",
    version=__version__,
    description=
      "#1 quality TLS certs while you wait, for the discerning tester",
    long_description=open("README.rst").read(),
    author="Nathaniel J. Smith",
    author_email="njs@pobox.com",
    license="MIT -or- Apache License 2.0",
    packages=find_packages(),
    url="https://github.com/python-trio/trustme",
    install_requires=["cryptography"],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: System :: Networking",
    ])
