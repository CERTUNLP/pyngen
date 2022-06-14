import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open('pyngen.egg-info/requirements.txt') as f:
    required = f.read().splitlines()
# DEPENDENCIES = open('requirements.txt', 'r').read().split('\n')
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
