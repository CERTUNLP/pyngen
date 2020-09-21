import setuptools
with open("README.md", "r") as fh:
    long_description = fh.read()

DEPENDENCIES = open('requirements.txt', 'r').read().split('\n')

setuptools.setup(
    name='pyngen',
    version='0.1.45',
    scripts=['pyngen/ngen'],
    author="CERTUNLP",
    author_email="soporte@cert.unlp.edu.ar",
    description="Ngen REST. A python library for using Ngen",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CERTUNLP/pyngen",
    packages=['pyngen'],
    install_requires=DEPENDENCIES,
    classifiers=[
        "Programming Language :: Python :: 3",
    ]
)
