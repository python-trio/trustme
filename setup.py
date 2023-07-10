from setuptools import setup, find_packages

# defines __version__
exec(open("src/trustme/_version.py").read())

setup(
    name="trustme",
    version=__version__,
    description=
      "#1 quality TLS certs while you wait, for the discerning tester",
    long_description=open("README.rst").read(),
    author="Nathaniel J. Smith",
    author_email="njs@pobox.com",
    license="MIT OR Apache-2.0",
    packages=find_packages(where="src"),
    package_data={
        'trustme': ['py.typed'],
    },
    package_dir={'': 'src'},
    url="https://github.com/python-trio/trustme",
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=3.1",
        "idna>=2.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Testing",
    ])
