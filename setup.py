#!/usr/bin/env python
# -*- coding:utf-8 -*-

from setuptools import setup


long_description = open("README.rst", "r").read()

classifiers = [
            "Programming Language :: Python",
            "Programming Language :: Python :: 2",
            "Programming Language :: Python :: 3",
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "Topic :: Security",
            "Topic :: Software Development :: Libraries :: Python Modules"]

metadata = {'name': "simple-rbac",
            'version': "0.1.1",
            'description': "A simple role based access control utility",
            'long_description': long_description,
            'keywords': "rbac permission acl access-control",
            'author': "Jiangge Zhang",
            'author_email': "tonyseek@gmail.com",
            'url': "http://github.tonyseek.com/simple-rbac/",
            'license': "MIT License",
            'packages': ["rbac"],
            'zip_safe': True,
            'platforms': "any",
            'test_suite': "tests.run_tests",
            'classifiers': classifiers}

if __name__ == "__main__":
    setup(**metadata)
