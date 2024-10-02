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
    name="pyngen_django",
    version="0.1.50",
    scripts=["pyngen_django/ngen"],
    author="CERTUNLP",
    author_email="soporte@cert.unlp.edu.ar",
    description="Ngen REST. A python library for using Ngen",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CERTUNLP/pyngen",
    packages=["pyngen_django"],
    install_requires=required,
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
)
