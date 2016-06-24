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


class TestRuleOptions(filter_setup.BaseClass, unittest.TestCase):
    """
    test class that shows basic rule option validation
    """
    def run_rules(self, rule, tests, echo=False, times=None):
        """
        Run each rule, and return the data that was generated.
        """
        if times is None:
            times = 1
        self.write_rules(rule)
        server = self.start_server()
        for data in tests:
            client_data = data
            expected = data

            if isinstance(data, tuple):
                client_data, expected = data

            self.start_filter()
            client = self.start_client()

            server_client = server.accept()[0]
            self.sockets.append(server_client)

            for _ in range(times):
                # print "SENDING", repr(client_data)
                self.send_all(client, client_data)
                server_got = server_client.recv(len(client_data))
                self.assertEqual(server_got, expected)
                # print "GOT", repr(server_got)

                test_data = None
                if echo:
                    test_data = server_got
                else:
                    test_data = self.random_string(10)

                self.send_all(server_client, test_data)
                self.assertEqual(client.recv(len(test_data)), test_data)

            results = self.stop_filter()
#            print ""
#            for result in results:
#                result = result[:-1]
#                print "RESULT: %s" % result

#            print repr(results)
            self.assertEqual(len(results), len(tests[data]),
                             "testing %s wrong record count (%d vs %d)" %
                             (repr(data), len(results), len(tests[data])))

            for idx, value in enumerate(tests[data]):
                self.assertIn(value, results[idx],
                              "testing %s.  got %s expected %s" %
                              (repr(data), repr(value), repr(results[idx])))
        server.close()

    @timeout(30)
    def test_content_ordering(self):
        """
            Rule looking for A, then B.
            Should match on "AB" and "ACB" and "AZZZZZZB"
            Should not match on "BA"
        """
        rule = 'alert (name:"test"; match:"A"; match:"\\x4242";)'

        tests = {
            "AB42": ["proxying connection from",
                     "INFO : filter matched: 'test'"],
            "AB42C": ["proxying connection from",
                      "INFO : filter matched: 'test'"],
            "AZZZZZZZZZB42": ["proxying connection from",
                              "INFO : filter matched: 'test'"],
            "AZZZZZZZZZ": ["proxying connection from"],
            "B42A": ["proxying connection from"],
        }

        self.run_rules(rule, tests)

    @timeout(30)
    def test_content_skip(self):
        """
            Rule looking for A, then B, with gap of 3 bytes
            Should match on "A123B" and "A1234B" but not "AB" and "A12B"
        """
        rule = 'alert (name:"test"; match:"A"; skip:3; match:"B";)'

        tests = {
            "A123B": ["proxying connection from",
                      "INFO : filter matched: 'test'"],
            "A1234B": ["proxying connection from",
                       "INFO : filter matched: 'test'"],
            "A12B": ["proxying connection from"],
            "AB": ["proxying connection from"],
        }

        self.run_rules(rule, tests)

    @timeout(30)
    def test_content_within(self):
        """
            Rule looking for A, then B within 3 bytes
            Should match on "AB" and "A12B" but not "A123B" and "A1234"
        """
        rule = 'alert (name:"test"; match:"A"; match:"B", 3;)'

        tests = {
            "A12B": ["proxying connection from",
                     "INFO : filter matched: 'test'"],
            "AB": ["proxying connection from",
                   "INFO : filter matched: 'test'"],
            "A123B": ["proxying connection from"],
            "A1234": ["proxying connection from"],
        }

        self.run_rules(rule, tests)

    @timeout(30)
    def test_content_within_skip(self):
        """
            Rule looking for A, skip 2 bytes, then B within 3 bytes
            Should match on "A12B" and "A1212B" but not "A12123B"
        """
        rule = 'alert (name:"test"; match:"A"; skip:2; match:"B", 3;)'

        tests = {
            "A12B": ["proxying connection from",
                     "INFO : filter matched: 'test'"],
            "A1212B": ["proxying connection from",
                       "INFO : filter matched: 'test'"],
            "A12123B": ["proxying connection from"],
            "A121234": ["proxying connection from"],
        }

        self.run_rules(rule, tests)

    @timeout(30)
    def test_side_server_content(self):
        """
            Rule looking for AB from the server.  Only the client traffic is
                "AB", server traffic is random.
        """
        rule = 'alert (name:"test"; side:server; match:"AB";)'

        tests = {
            "AB": ["proxying connection from"],
        }

        self.run_rules(rule, tests)

    @timeout(30)
    def test_side_content(self):
        """
            Rule looking for AB from the client.  Should match.
        """
        rule = 'alert (name:"test"; side:client; match:"AB";)'

        tests = {
            "AB": ["proxying connection from",
                   "INFO : filter matched: 'test'"],
            "xxxxxxxABxxxxx": ["proxying connection from",
                               "INFO : filter matched: 'test'"],
            "A12B": ["proxying connection from"],
        }

        self.run_rules(rule, tests)

    @timeout(30)
    def test_state(self):
        """
            Rule looking for AB then CD, but as different rules.

            "ABCD" should cause test1 and test2 to alert, but not test3
            "CDAB" should cause test1 to alert, but not test2 or test3
            "CD" should cause no alerts to generate
        """
        rule = ('alert (name:"test1"; match:"AB"; state:set,test;)\n'
                'alert (name:"test2"; match:"CD"; state:is,test;)\n'
                'alert (name:"test3"; match:"BC"; state:not,not_tested;)\n')

        tests = {
            "ABCD": ["proxying connection from",
                     "INFO : filter matched: 'test1'",
                     "INFO : filter matched: 'test2'"],
            "CDAB": ["proxying connection from",
                     "INFO : filter matched: 'test1'"],
            "CD": ["proxying connection from"],
        }

        self.run_rules(rule, tests)

    @timeout(30)
    def test_not_state(self):
        """
            Send "ABCDEF".  test1 should alert, test2 should alert, test3
                should not

            "ABCDEF" should cause test1, test2, and test3 to alert
            "ABEFCD" should cause test1 and test2 to alert, but not test3
            "CDEF" should cause no alerts
        """

        rule = ('alert(name:"test1"; match:"AB"; state:set,a; state:set,b;)\n'
                'alert(name:"test2"; match:"CD"; state:is,a; state:unset,b;)\n'
                'alert(name:"test3"; match:"EF"; state:is,a; state:not,b;)\n')

        tests = {
            "ABCDEF": ["proxying connection from",
                       "INFO : filter matched: 'test1'",
                       "INFO : filter matched: 'test2'",
                       "INFO : filter matched: 'test3'"],
            "ABEFCD": ["proxying connection from",
                       "INFO : filter matched: 'test1'",
                       "INFO : filter matched: 'test2'"],
            "CDEF": ["proxying connection from"],
        }

        self.run_rules(rule, tests)

    @timeout(30)
    def test_replace(self):
        """
            This test changes the embedded TCP server to an echo server.

            test1 looks for "AB" from the client, and replaces it with "XY"
            test2 looks for "XY" from the server

            "AB" should cause test1 and test2 to alert
            "XY" should cause test2 to alert
        """

        rule = ('alert(name:"test1"; side:client; match:"AB"; replace:"XY";)\n'
                'alert(name:"test2"; side:server; match:"XY";)\n')

        tests = {
            ("AB", "XY"): ["proxying connection from",
                           "INFO : filter matched: 'test1'",
                           "INFO : filter matched: 'test2'"],
            "XY": ["proxying connection from",
                   "INFO : filter matched: 'test2'"],
            ("ABAB", "XYXY"): ["proxying connection from",
                           "INFO : filter matched: 'test1'",
                           "INFO : filter matched: 'test1'",
                           "INFO : filter matched: 'test2'",
                           "INFO : filter matched: 'test2'"],
        }

        self.run_rules(rule, tests, echo=True)

    @timeout(30)
    def test_admit(self):
        """
            Try sending 'AB' through the same rules, except one is alert, the
            other is admit.

            The first test should alert, the second should not.
        """

        rule = 'alert (name:"test"; match:"AB";)'

        tests = {
            "AB": ["proxying connection from",
                   "INFO : filter matched: 'test'"],
        }

        self.run_rules(rule, tests)

        rule = rule.replace('alert', 'admit')
        tests = {"AB": ["proxying connection from"]}

        self.run_rules(rule, tests)

    @timeout(30)
    def test_admit_consume(self):
        """
            Try sending 'ABC' through two rules, the first is an admit that
            allows "AB" the second should verify admit flushed the buffer, by
            not alerting on "BC".

            There should be no alerting, if admit flushes as we expect.
        """

        rule = ('admit (name:"one"; match:"AB";)\n'
                'alert (name:"two"; match:"BC";)')

        tests = {
            "ABC": ["proxying connection from"]
        }

        self.run_rules(rule, tests)

    @timeout(30)
    def test_flush(self):
        """
            Send "AB", then get "AB", twice.  The first set of rules should
            alert 'test' twice.  The second should not alert at all, as the
            'flush:client' should prevent the client buffer from ever consuming
            enough data.
        """

        rule = ('alert (name:"test"; side:client; match:"ABAB";)')

        tests = {
            "AB": ["proxying connection from", "INFO : filter matched: 'test'"],
        }
        self.run_rules(rule, tests, echo=True, times=2)

        rule = ('alert (name:"test1"; side:client; match:"ABAB";)\n'
                'admit (name:"test2"; side:server; match:"AB"; flush:client;)\n')

        tests = {
            "AB": ["proxying connection from"]
        }

        self.run_rules(rule, tests, echo=True, times=2)

    @timeout(30)
    def test_match_hex(self):
        """
            Send "AB\x4141".  Should match ABA41, should not match ABAA.
        """

        rule = ('alert (name:"test"; match:"AB\\x4141";)')

        tests = {
            "ABA41": ["proxying connection from", "INFO : filter matched: 'test'"],
            "ABAA": ["proxying connection from"],
        }
        self.run_rules(rule, tests)

    @timeout(30)
    def test_repeated_content(self):
        """
            This test changes the embedded TCP server to an echo server.

            test1 looks for "AB" from the client
            test2 looks for "AB" from the client and replaces it with "XY"
            test3 looks for "XY" from the server

            "AB" should cause test1 and test3 to alert
            "XY" should cause test3 to alert
            "ABAB" should cause test1 and test3 to alert twice
        """

        rule = ('alert(name:"test1"; side:client; match:"AB"; replace:"XY";)\n'
                'block(name:"test2"; side:client; match:"AB";)\n'
                'alert(name:"test3"; side:server; match:"XY";)\n')

        tests = {
            ("AB", "XY"): ["proxying connection from",
                           "INFO : filter matched: 'test1'",
                           "INFO : filter matched: 'test3'"],
            "XY": ["proxying connection from",
                   "INFO : filter matched: 'test3'"],
            ("ABAB", "XYXY"): ["proxying connection from",
                           "INFO : filter matched: 'test1'",
                           "INFO : filter matched: 'test1'",
                           "INFO : filter matched: 'test3'",
                           "INFO : filter matched: 'test3'"],
            ("abcdAB", "abcdXY"): ["proxying connection from",
                           "INFO : filter matched: 'test1'",
                           "INFO : filter matched: 'test3'"],
        }

        self.run_rules(rule, tests, echo=True)
    
    @timeout(30)
    def test_states_reset(self):
        """
            This test changes the embedded TCP server to an echo server.

            test1 looks for "AB" from the client, and sets the state 'foo', then looks for "CD" replaces it with "XY"
            test2 looks if the state 'foo' is set, and drops the session
            test3 looks for "AB" from the server

            "ABCD" should cause test1 and test2 to alert
            "ABAB" should cause test3 to alert
        """

        rule = ('alert(name:"test1"; side:client; match:"AB"; state:set,foo; match:"AB";)\n'
                'block(name:"test2"; state:is,foo;)\n'
                'alert(name:"test3"; side:server; match:"AB";)\n')

        tests = {
            ("ABCD", "ABCD"): ["proxying connection from", "INFO : filter matched: 'test3'"],
            ("ABAB", ""): ["proxying connection from", "INFO : blocking connection: filter matched 'test2'", "INFO : closed connection"],
        }

        self.run_rules(rule, tests, echo=True)

    @timeout(30)
    def test_any_rune(self):
        """
            Rule that tests regex for things that are not characters.
            Should match on "A" but not on "\x90"
        """
        rule = 'alert (name:"rune"; regex:".{64}";)'

        tests = {
            "A"*64: ["proxying connection from", "INFO : filter matched: 'rune'"],
            "\x90"*64: ["proxying connection from"],
        }

        self.run_rules(rule, tests, echo=False)

    @timeout(30)
    def test_any_byte(self):
        """
            Rule that tests regex for things that are not characters.
            Should match on "A" and "\x90"
        """
        rule = 'alert (name:"bytes"; regex:"\C{64}";)'

        tests = {
            "A"*64: ["proxying connection from", "INFO : filter matched: 'bytes'"],
            "\x90"*64: ["proxying connection from", "INFO : filter matched: 'bytes'"],
        }

        self.run_rules(rule, tests, echo=False)

if __name__ == '__main__':
    unittest.main()
