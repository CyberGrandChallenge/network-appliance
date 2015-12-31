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

from functools import wraps
import signal

__all__ = ['timeout']


class TimeoutError(Exception):
    """ A simple Exception based class as to allow users to catch timeout
    exceptions """
    pass


def timeout(seconds):
    """ A decorator to provide timeouts of a function.

    Usage:
        @timeout(10)
        def foo():
            ....

    """
    def decorator(func):
        """ Decorator method, wrapping the specified func """
        def cb_sigalrm(signum, frame):
            """ signal callback handler, should always raise TimeoutError """
            raise TimeoutError()

        def wrapper(*args, **kwargs):
            """ Actual timeout implementation, sets and unsets the alarm as
            needed """
            orig_handler = signal.signal(signal.SIGALRM, cb_sigalrm)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            signal.signal(signal.SIGALRM, orig_handler)
            return result

        return wraps(func)(wrapper)

    return decorator
