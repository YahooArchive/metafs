#!/usr/bin/env python
# Copyright (c) 2015, Yahoo Inc.
# Copyrights licensed under the BSD
# See the accompanying LICENSE.txt file for terms.
"""
test_metafs
----------------------------------

Tests for `metafs` module.
"""
import unittest


# Any methods of the class below that begin with "test" will be executed
# when the the class is run (by calling unittest.main()
class TestMetafs(unittest.TestCase):

    def test_metafs_import(self):
        import metafs

if __name__ == '__main__':
    unittest.main()
