import unittest


def run_tests():
    loader = unittest.TestLoader()
    suite = loader.discover("tests")
    return suite
