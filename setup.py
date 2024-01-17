import setuptools
import os

with open("README.md", "r") as fh:
    long_description = fh.read()

req_file = 'pyngen.egg-info/requirements.txt'
if not os.path.isfile('pyngen.egg-info/requirements.txt'):
    req_file = 'requirements.txt'

with open(req_file) as f:
    required = f.read().splitlines()
# pensar en cambiar de vuelta filemime por Magic

setuptools.setup(
    name='pyngen',
    version='0.1.50',
    scripts=['pyngen/ngen'],
    author="CERTUNLP",
    author_email="soporte@cert.unlp.edu.ar",
    description="Ngen REST. A python library for using Ngen",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CERTUNLP/pyngen",
    packages=['pyngen'],
    install_requires=required,
    classifiers=[
        "Programming Language :: Python :: 3",
    ]
)
