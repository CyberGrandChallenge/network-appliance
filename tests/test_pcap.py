#!/usr/bin/python
"""
Copyright (C) 2016 - Brian Caswell <bmc@lungetech.com>

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
import socket

sys.path = ['.'] + sys.path
os.environ['PYTHONPATH'] = ':'.join(sys.path)

from timeout import timeout
import filter_setup


class TestPcap(filter_setup.BaseClass, unittest.TestCase):
    CLIENT, SERVER = (0, 1)
    HEADER_LEN = 15

    def setup_packets(self, port=1999):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_sock.bind(('', port))
        self.sockets.append(self.udp_sock)

    def get_packet(self):
        data = self.udp_sock.recvfrom(0xFFFF)[0]

        header = data[:TestPcap.HEADER_LEN]
        message = data[TestPcap.HEADER_LEN:]

        assert len(data) >= TestPcap.HEADER_LEN
        csid, connection_id, msg_id, msg_len, side = struct.unpack('<LLLHB',
                                                                   header)
        self.assertEqual(len(message), msg_len)
        return (csid, connection_id, msg_id, msg_len, side, message)

    @timeout(5)
    def test_single(self):
        self.write_rules('alert (name:"test"; regex:".*A.*";)')
        self.start_filter(pcap_host='127.0.0.1', pcap_port=1999)
        self.setup_packets()

        server = self.start_server()
        client = self.start_client()

        server_client = server.accept()[0]
        self.sockets.append(server_client)

        data = "AAAA"
        self.send_all(client, data)
        self.assertEqual(server_client.recv(len(data)), data)

        response = self.get_packet()
        self.assertEqual(response, (0, 0, 0, len(data), TestPcap.SERVER, data))

        data = "BBBA"
        self.send_all(server_client, data)
        self.assertEqual(client.recv(len(data)), data)

        response = self.get_packet()
        self.assertEqual(response, (0, 0, 1, len(data), TestPcap.CLIENT, data))

        data = "BBBBB"
        self.send_all(server_client, data)
        self.assertEqual(client.recv(len(data)), data)

        response = self.get_packet()
        self.assertEqual(response, (0, 0, 2, len(data), TestPcap.CLIENT, data))

        data = "CCCA"
        self.send_all(server_client, data)
        self.assertEqual(client.recv(len(data)), data)

        response = self.get_packet()
        self.assertEqual(response, (0, 0, 3, len(data), TestPcap.CLIENT, data))

        results = self.stop_filter()
        self.assertEqual(len(results), 4)

    def test_two_clients(self):
        self.write_rules('alert (name:"test"; regex:".*A.*";)')
        self.start_filter(pcap_host='127.0.0.1', pcap_port=1999)
        self.setup_packets()

        server = self.start_server()
        client1 = self.start_client()
        server_client1 = server.accept()[0]
        self.sockets.append(server_client1)

        client2 = self.start_client()
        server_client2 = server.accept()[0]
        self.sockets.append(server_client2)

        data = "AAAA"
        self.send_all(client1, data)
        self.assertEqual(server_client1.recv(len(data)), data)

        response = self.get_packet()
        self.assertEqual(response, (0, 0, 0, len(data), TestPcap.SERVER, data))

        data = "BBBA"
        self.send_all(server_client2, data)
        self.assertEqual(client2.recv(len(data)), data)

        response = self.get_packet()
        self.assertEqual(response, (0, 1, 0, len(data), TestPcap.CLIENT, data))

        data = "BBBBB"
        self.send_all(server_client1, data)
        self.assertEqual(client1.recv(len(data)), data)

        response = self.get_packet()
        self.assertEqual(response, (0, 0, 1, len(data), TestPcap.CLIENT, data))

        data = "CCCA"
        self.send_all(server_client2, data)
        self.assertEqual(client2.recv(len(data)), data)

        response = self.get_packet()
        self.assertEqual(response, (0, 1, 1, len(data), TestPcap.CLIENT, data))

        results = self.stop_filter()
        self.assertEqual(len(results), 5)

    @timeout(5)
    def test_pcap_with_negotiate(self):
        count = 5
        chunks = []
        for _ in range(count):
            data = "A" * 50
            chunks += [struct.pack('<LL', 3, len(data)) + data]
        count_data = struct.pack('<L', count)

        self.write_rules('alert (name:"test"; regex:".*(A|B|C).*";)')
        self.start_filter(pcap_host='127.0.0.1',
                          pcap_port=1999,
                          negotiate=True)
        self.setup_packets()

        server = self.start_server()
        client = self.start_client()

        server_client = server.accept()[0]
        self.sockets.append(server_client)

        self.send_all(client, count_data)
        self.assertEqual(self.recv_size(server_client, len(count_data)),
                         count_data)

        for chunk in chunks:
            self.send_all(client, chunk)
            self.assertEqual(self.recv_size(server_client, len(chunk)), chunk)

        response = "B" * 4
        self.send_all(server_client, response)
        self.assertEqual(self.recv_size(client, len(response)), response)

        data = "CCCC"
        self.send_all(client, data)
        self.assertEqual(server_client.recv(len(data)), data)

        response = self.get_packet()
        self.assertEqual(response, (0, 0, 0, len(data), TestPcap.SERVER, data))

        results = self.stop_filter()
        self.assertEqual(len(results), 2)


if __name__ == '__main__':
    unittest.main()
