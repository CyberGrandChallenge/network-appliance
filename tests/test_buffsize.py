#!/usr/bin/python
"""
Copyright (C) 2015 - Brian Caswell <bmc@lungetech.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import unittest
import os
import sys

sys.path = ['.'] + sys.path
os.environ['PYTHONPATH'] = ':'.join(sys.path)

from timeout import timeout
import filter_setup


class TestRingBuffer(filter_setup.BaseClass, unittest.TestCase):
    def large_write(self, window, rules, data):
        self.write_rules(rules)
        self.start_filter(buffer_size=window)
        server = self.start_server()
        client = self.start_client()

        server_client = server.accept()[0]
        self.sockets.append(server_client)

        while len(data):
            chunk = data[:10]
            self.assertEqual(self.send_all(client, chunk), len(chunk))
            self.assertEqual(self.recv_size(server_client, len(chunk)), chunk)
            data = data[len(chunk):]

        data = "response"
        self.assertEqual(self.send_all(server_client, data), len(data))
        self.assertEqual(self.recv_size(client, len(data)), data)

        return self.stop_filter()

    @timeout(30)
    def run_test(self, window, size, expected):
        rules = 'alert (name:"one"; regex:"A{%d}B";)' % size
        data = "A" * size + "B"
        results = self.large_write(window, rules, data)

        self.assertEqual(len(results), len(expected))
        for i, value in enumerate(expected):
            self.assertIn(value, results[i])

    def test_verify_large_buffer(self):
        self.run_test(1000, 1000 - 1, ["proxying connection from",
                                       "filter matched:"])

    def test_verify_oversize_buffer(self):
        self.run_test(1000, 1000, ["proxying connection from",
                                   "truncating inspection buffer"])


if __name__ == '__main__':
    unittest.main()
