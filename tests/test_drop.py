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


class TestFilterBlock(filter_setup.BaseClass, unittest.TestCase):
    @timeout(5)
    def test_block_segmented_overflow(self):
        rule = 'block (name:"test"; match:"AAAAAAAAAAAAAAA";)'
        self.write_rules(rule)
        self.start_filter()
        server = self.start_server()
        client = self.start_client()

        server_client = server.accept()[0]
        self.sockets.append(server_client)

        data = "A" * 10
        self.send_all(client, data)
        self.assertEqual(server_client.recv(len(data)), data)

        data = self.random_string(10)
        self.send_all(server_client, data)
        self.assertEqual(client.recv(len(data)), data)

        data = "A" * 10
        self.send_all(client, data)
        self.assertEqual(server_client.recv(len(data)), '')

        results = self.stop_filter()
        self.assertEqual(len(results), 3)
        self.assertIn(" - INFO : proxying connection from ('127.0.0.1', ",
                      results[0])
        self.assertIn(" - INFO : blocking connection: filter matched 'test'",
                      results[1])
        self.assertIn(" - INFO : closed connection from ('127.0.0.1',",
                      results[2])

    @timeout(5)
    def test_block_segmented_overflow_regex(self):
        rule = 'block (name:"test"; regex:"A{15,}";)'
        self.write_rules(rule)
        self.start_filter()
        server = self.start_server()
        client = self.start_client()

        server_client = server.accept()[0]
        self.sockets.append(server_client)

        data = "A" * 10
        self.send_all(client, data)
        self.assertEqual(server_client.recv(len(data)), data)

        data = self.random_string(10)
        self.send_all(server_client, data)
        self.assertEqual(client.recv(len(data)), data)

        data = "A" * 10
        self.send_all(client, data)
        self.assertEqual(server_client.recv(len(data)), '')

        results = self.stop_filter()
        self.assertEqual(len(results), 3)
        self.assertIn(" - INFO : proxying connection from ('127.0.0.1', ",
                      results[0])
        self.assertIn(" - INFO : blocking connection: filter matched 'test'",
                      results[1])
        self.assertIn(" - INFO : closed connection from ('127.0.0.1',",
                      results[2])

    @timeout(5)
    def test_two_clients_one_overflow(self):
        rule = 'block (name:"test"; regex:"A{15,}";)'
        self.write_rules(rule)
        self.start_filter()

        server = self.start_server()
        client1 = self.start_client()
        server_client1 = server.accept()[0]

        client2 = self.start_client()
        server_client2 = server.accept()[0]
        self.sockets.append(server_client1)
        self.sockets.append(server_client2)

        data = "A" * 10
        self.send_all(client1, data)
        self.assertEqual(server_client1.recv(len(data)), data)

        data = self.random_string(30)
        self.send_all(client2, data)
        self.assertEqual(server_client2.recv(len(data)), data)

        data = "A" * 10
        self.send_all(client1, data)
        # At this point, the connection should be terminated, and no data is
        # recved
        self.assertEqual(server_client1.recv(len(data)), '')

        data = self.random_string(30)
        self.send_all(server_client1, data)
        # No data should make it back to the client of the terminated session
        self.assertEqual(client1.recv(len(data)), '')

        data = self.random_string(30)
        self.send_all(server_client2, data)
        # the second session should still be alive
        self.assertEqual(client2.recv(len(data)), data)

        results = self.stop_filter()
        self.assertEqual(len(results), 4)
        self.assertIn(" - INFO : proxying connection from ('127.0.0.1', ",
                      results[0])
        self.assertIn(" - INFO : proxying connection from ('127.0.0.1', ",
                      results[1])
        self.assertIn(" - INFO : blocking connection: filter matched 'test'",
                      results[2])
        self.assertIn(" - INFO : closed connection from ('127.0.0.1',",
                      results[3])


if __name__ == '__main__':
    unittest.main()
