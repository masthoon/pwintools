from setuptools import setup

PKG_NAME = "PWiNTOOLS"
VERSION  = "0.31"


setup(
    name = PKG_NAME,
    version = VERSION,
    author = 'Mastho',
    author_email = 'none',
    description = 'Windows basic pwntools - exploit development library',
    license = 'MIT',
    keywords = 'windows python exploit',
    url = 'https://github.com/masthoon/pwintools',
    py_modules=['pwintools'],
    install_requires=[
        'pyserial==3.0.1', #for windows XP. Otherwise use the latest version 
    ],
    dependency_links=[
        'git+git://github.com/hakril/PythonForWindows@master#egg=PythonForWindows-0.4',
    ]
)