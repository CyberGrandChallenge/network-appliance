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
import unittest
import sys
sys.path = ['.'] + sys.path
import ids


class TestParser(unittest.TestCase):
    BASE = [('rule_type', 'alert'), ('name', ['"test"'])]

    def test_white_space(self):
        parser = ids.ids_parser.ids_parser()
        self.assertEqual(parser.parse('# foo'), [])
        self.assertEqual(parser.parse(' ' * 9000), [])
        self.assertEqual(parser.parse('  # foo '), [])

    def test_rule(self):
        parser = ids.ids_parser.ids_parser()

        rule = 'alert (name:"test"; match:"foo";)'
        expected = self.BASE +[('option', ('match', ['"foo"']))]
        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_whitespace(self):
        parser = ids.ids_parser.ids_parser()

        rule = 'alert (name : "test" ; match : "foo" ; ) '
        expected = self.BASE +[('option', ('match', ['"foo"']))]
        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_no_spaces(self):
        parser = ids.ids_parser.ids_parser()

        rule = 'alert(name:"test";match:"foo";)'
        expected = self.BASE +[('option', ('match', ['"foo"']))]
        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_with_comments(self):
        parser = ids.ids_parser.ids_parser()

        rule = 'alert (name:"test"; match:"foo";) # with comments'
        expected = self.BASE +[('option', ('match', ['"foo"']))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_with_depth(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; match:"foo", 4;)'
        expected = self.BASE +[('option', ('match', ['"foo"', ('depth',
                                                               ["4"])]))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_with_replace(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; match:"foo"; replace:"bar";)'
        expected = self.BASE +[('option', ('match', ['"foo"', ('replace',
                                                               ['"bar"'])]))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_with_depth_replace(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; match:"foo", 4; replace:"bar";)'
        expected = self.BASE +[('option', ('match', ['"foo"', ('depth', ['4']),
                                                     ('replace', ['"bar"'])]))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_match_hex(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; match:"fo\\x41 bar \x4141";)'
        expected = self.BASE +[('option', ('match', ['"fo\\x41 bar \x4141"']))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_multi_match(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; match:"foo"; match:"bar";)'
        expected = self.BASE +[('option', ('match', ['"foo"'])),
                               ('option', ('match', ['"bar"']))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_regex(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; regex:"a\\;b";)'
        expected = self.BASE +[('option', ('regex', ['"a\\;b"']))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_server(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; side:server;)'
        expected = self.BASE +[('option', ('side', ['server']))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_client(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; side:client;)'
        expected = self.BASE +[('option', ('side', ['client']))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_state_is(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; state:is,foo_bar;)'
        expected = self.BASE +[('option', ('state', ['is', 'foo_bar']))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_state_not(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; state:not,foo_bar;)'
        expected = self.BASE +[('option', ('state', ['not', 'foo_bar']))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_state_set(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; state:set,foo_bar;)'
        expected = self.BASE +[('option', ('state', ['set', 'foo_bar']))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_state_unset(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; state:unset,foo_bar;)'
        expected = self.BASE +[('option', ('state', ['unset', 'foo_bar']))]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_state_flush_same(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; side:client; flush:client;)'
        expected = self.BASE +[('option', ('side', ['client'])),
                               ('flush', ['client'])]

        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_rule_state_flush_different(self):
        parser = ids.ids_parser.ids_parser()
        rule = 'alert (name:"test"; side:client; flush:server;)'
        expected = self.BASE +[('option', ('side', ['client'])),
                               ('flush', ['server'])]


        self.assertEqual(parser.parse(rule), expected)

        rule = rule.replace('alert', 'block')
        expected[0] = ('rule_type', 'block')
        self.assertEqual(parser.parse(rule), expected)

    def test_bad_rules(self):
        parser = ids.ids_parser.ids_parser()
        bad_rules = [
            'alert (name:"";)',
            'alert (name:"foo")',
            'alert (name:"foo"; name:"foo";)',
            'alert (name:"foo";',
            'alert name:"foo";',
            'alert (ame:"foo";)',
            'alert (name:"foo"; # )',
            'alert (name:"foo"; match:"";)',
            'alert (name:"foo"; match:"" 4;)',
            'alert (name:"foo"; match:;)',
            'alert (name:"foo"; regex:"";)',
            'alert (name:"foo"; match:"\"";)',
            'alert (name:"foo"; match:";";)',
            'alert (name:"foo"; state:set,foo bar;)',
            'alert (name:"foo"; state:set foo;)',
            'alert (name:"foo"; state:set,foo"bar;)',
            'alert (name:"foo"; state:wut,foo;)',
            'alert (name:"foo"; state:;',
            'alert (name:"foo"; state:set;',
            'alert (name:"foo"; state:,foo;',
            'alert (name:"foo"; side:wut;)',
            'alert (name:"foo"; side:;)',
            'alert (name:"test";)',
            'alert (name:"test"; flush:bob;)',
            'alert (name:"test"; flush:client; match:"test";)',
            'alert (match:"test";)',
            'alert (match:"test"; name:"test";)',
        ]

        for rule in bad_rules:
            with self.assertRaises(SyntaxError):
                parser.parse(rule)

    def test_examples(self):
        parser = ids.ids_parser.ids_parser()
        files = ['examples/%s' % f for f in os.listdir('examples')]
        files = [f for f in files if os.path.isfile(f)]
        files = [f for f in files if f.endswith('.rules')]
        for filename in files:
            with open(filename, 'r') as fh:
                for line in fh.readlines():
                    line = line.strip()
                    parser.parse(line)

if __name__ == '__main__':
    unittest.main()
