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
import struct
import os
import sys
import random

sys.path = ['.'] + sys.path
os.environ['PYTHONPATH'] = ':'.join(sys.path)

from timeout import timeout
import filter_setup


class TestNegotiate(filter_setup.BaseClass, unittest.TestCase):
    @timeout(5)
    def test_negotate_basic(self):
        content = "A" * 4
        response = "B" * 4

        rule = 'block (name:"test A"; match:"%s";)\n' % content
        rule += 'block (name:"test B"; match:"%s";)' % response

        content = struct.pack('<L', len(content)) + content

        self.write_rules(rule)
        self.start_filter(negotiate=True)
        server = self.start_server()
        client = self.start_client()

        server_client = server.accept()[0]
        self.sockets.append(server_client)

        # this should get passed implicitly
        client.sendall(content)
        self.assertEqual(server_client.recv(len(content)), content)
    
        # first 4 bytes of the response are ignored as status codes
        server_client.sendall(response)
        self.assertEqual(client.recv(len(response)), response)

        # any arbitrary data back and forth
        for i in range(random.randint(5, 50)):
            if random.choice([0, 1]):
                content = "C" * random.randint(1, 100)
                client.sendall(content)
                self.assertEqual(server_client.recv(len(content)), content)
            else:
                content = "D" * random.randint(1, 100)
                server_client.sendall(content)
                self.assertEqual(client.recv(len(content)), content)

        # any further response is inspected
        server_client.sendall(response)
        self.assertEqual(client.recv(len(response)), '')

        results = self.stop_filter()
        self.assertEqual(len(results), 3)
        self.assertIn(" - INFO : proxying connection from ('127.0.0.1', ",
                      results[0])
        self.assertIn(" - INFO : blocking connection: filter matched 'test B'",
                      results[1])
        self.assertIn(" - INFO : closed connection from ('127.0.0.1',",
                      results[2])

    @timeout(5)
    def test_negotate_no_data(self):
        response = "A" * 4

        content = struct.pack('<L', 0)

        self.write_rules('')
        self.start_filter(negotiate=True)
        server = self.start_server()
        client = self.start_client()

        server_client = server.accept()[0]
        self.sockets.append(server_client)

        # this should get passed implicitly
        client.sendall(content)

        self.assertEqual(server_client.recv(len(content)), content)
      
        # first 4 bytes of the response are ignored as status codes
        server_client.sendall(response)
        self.assertEqual(client.recv(len(response)), response)

        server_client.sendall(response)
        self.assertEqual(client.recv(len(response)), response)

        results = self.stop_filter()
        print repr(results)
        self.assertEqual(len(results), 1)
        self.assertIn(" - INFO : proxying connection from ('127.0.0.1', ",
                      results[0])

    @timeout(5)
    def test_negotate_out_of_order_states(self):
        response = "A" * 4

        content = struct.pack('<L', 0)

        self.write_rules('')
        self.start_filter(negotiate=True)
        server = self.start_server()
        client = self.start_client()

        server_client = server.accept()[0]
        self.sockets.append(server_client)
        
        # first 4 bytes of the response are ignored as status codes
        server_client.sendall(response)
        self.assertEqual(client.recv(len(response)), '')

        results = self.stop_filter()
        print repr(results)
        self.assertEqual(len(results), 2)
        self.assertIn(" - INFO : proxying connection from ('127.0.0.1', ",
                      results[0])
        self.assertIn(" - INFO : closed connection from ('127.0.0.1',",
                      results[1])


if __name__ == '__main__':
    unittest.main()
