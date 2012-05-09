#!/usr/bin/env python
#-*- coding:utf-8 -*-

from setuptools import setup, find_packages


metadata = {'name': "Simple RBAC",
            'version': "0.1",
            'packages': find_packages(),
            'author': "TonySeek",
            'author_email': "tonyseek@gmail.com",
            'license': "MIT"}


if __name__ == "__main__":
    setup(**metadata)
