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

import os
import Queue
import random
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time


class BaseClass(object):
    """
    This class should be a mixin along with unittest.TestCase for testing
    cb-proxy rules.
    """
    LISTEN_PORT = 6666
    SERVER_PORT = 7777

    def setUp(self):
        """ used by unittest.TestCase before each test_* method """
        self.tmp_dir = tempfile.mkdtemp('ids_rules')
        self.process = None
        self.queue = None
        self.sockets = []
        self.threads = []
        self.basic_filename = os.path.join(self.tmp_dir, 'test.rules')

    def tearDown(self):
        """ used by unittest.TestCase after each test_* method """
        shutil.rmtree(self.tmp_dir)

        for sock in self.sockets:
            sock.close()

        self.stop_filter()

    def stop_filter(self):
        """ Stop the running cb-proxy, cleanup all of the potential state, and
        return any output from cb-proxy """
        if self.process is not None:
            self.process.terminate()
            self.process.wait()
            self.process = None

        for thread in self.threads:
            thread.join()
        self.threads = []

        results = []
        if self.queue is not None and not self.queue.empty():
            null_count = 0
            while null_count < 2:
                out = self.queue.get()
                if out is None:
                    null_count += 1
                else:
                    results.append(out)
        return results

    def start_filter(self,
                     rule_filename=None,
                     max_connections=None,
                     negotiate=False,
                     buffer_size=None,
                     pcap_host=None,
                     pcap_port=None):
        """ Start cb-proxy in the background """
        assert self.process is None
        assert self.threads == []
        if rule_filename is None:
            rule_filename = self.basic_filename

        def log_thread(log, queue):
            """ callback for the thread for logging output from cb-proxy """
            for line in iter(log.readline, ''):
                print line
                queue.put(line)
            log.close()
            queue.put(None)

        cmd = ['bin/cb-proxy',
               '--listen_port',
               '%d' % BaseClass.LISTEN_PORT,
               '--host',
               '127.0.0.1',
               '--port',
               '%d' % BaseClass.SERVER_PORT,
               # '--debug',
               '--rules',
               rule_filename]

        if max_connections:
            cmd += ['--max_connections', '%d' % max_connections]

        if negotiate:
            cmd += ['--negotiate']

        if buffer_size is not None:
            cmd += ['--buffer_size', '%d' % buffer_size]

        if pcap_host:
            cmd += ['--pcap_host', pcap_host]

        if pcap_port:
            cmd += ['--pcap_port', '%d' % pcap_port]

        print ' '.join(cmd)
        self.process = subprocess.Popen(cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)

        queue = Queue.Queue()

        for log_fh in [self.process.stdout, self.process.stderr]:
            thread = threading.Thread(target=log_thread, args=(log_fh, queue))
            thread.start()
            self.threads.append(thread)

        time.sleep(1)
        self.queue = queue

    @staticmethod
    def random_string(size):
        """ Generate a random string of a specified size """
        values = list(range(0, 255))
        return ''.join([chr(random.choice(values)) for _ in range(size)])

    def start_server(self):
        """ Start a local TCP server """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sockets.append(sock)
        self.setup_socket(sock)
        sock.bind(('127.0.0.1', BaseClass.SERVER_PORT))
        sock.listen(50)
        return sock

    def start_client(self):
        """ Create a local TCP connection """
        sock = socket.create_connection(('127.0.0.1', BaseClass.LISTEN_PORT))
        self.sockets.append(sock)
        self.setup_socket(sock)
        return sock

    @staticmethod
    def setup_socket(sock):
        """ method to setup a few basic socket options needed for speed &
        socket reuse """
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack('ii', 1, 5))

    def write_rules(self, rules):
        """ Write the provided rules to disk """
        with open(self.basic_filename, 'w') as rule_fh:
            rule_fh.write(rules)

    def recv_size(self, sock, size):
        data = ''
        while len(data) < size:
            data_read = sock.recv(size - len(data))
            data += data_read
            if len(data_read) == 0:
                break

        return data

    def send_all(self, sock, data):
        total_sent = 0
        while total_sent < len(data):
            sent = sock.send(data[total_sent:])
            total_sent += sent
            if sent == 0:
                break

        return total_sent
