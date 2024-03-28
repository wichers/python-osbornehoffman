import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="osbornehoffman",
    version="1.0.3",
    author="wichers",
    author_email="wichers@users.noreply.github.com",
    description="Python 3 package to interface with Osborne Hoffman panels.",
    license="MIT",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/wichers/python-osbornehoffman",
    packages=setuptools.find_packages(),
    install_requires=[
        'pycryptodome>=3.14.0',
        'crc>=6.1.1'
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
