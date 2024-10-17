import setuptools
import os

with open("README.md", "r") as fh:
    long_description = fh.read()

required = [
    "requests",
    "filemime",
    "click",
    "python-slugify",
]

setuptools.setup(
    name="pyngen",
    version="0.1.51",
    scripts=["pyngen/ngen"],
    author="CERTUNLP",
    author_email="soporte@cert.unlp.edu.ar",
    description="Ngen REST. A python library for using Ngen",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CERTUNLP/pyngen",
    packages=["pyngen"],
    install_requires=required,
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
)
