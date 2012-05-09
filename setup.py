#!/usr/bin/env python
#-*- coding:utf-8 -*-

from setuptools import setup, find_packages


metadata = {'name': "simple-rbac",
            'version': "0.1",
            'packages': find_packages()}


if __name__ == "__main__":
    setup(**metadata)
