#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

from . import event


class Engine(object):
    def __init__(self):
        pass

    def on_file_open(self, event):
        print('open: pid = %d, path = %s, timestamp = %s' % (
            event.pid, event.path, event.timestamp))

    def on_list_dir(self, event):
        print('listdir: pid = %d, path = %s, timestamp = %s' % (
            event.pid, event.path, event.timestamp))

    def on_file_read(self, event):
        print('read: pid = %d, path = %s, timestamp = %s' % (
            event.pid, event.path, event.timestamp))

    def on_file_write(self, event):
        print('write: pid = %d, path = %s, timestamp = %s' % (
            event.pid, event.path, event.timestamp))

    def on_file_unlink(self, event):
        print('unlink: pid = %d, path = %s, timestamp = %s' % (
            event.pid, event.path, event.timestamp))

    def on_file_close(self, event):
        print('close: pid = %d, path = %s, timestamp = %s' % (
            event.pid, event.path, event.timestamp))

    def on_crypto_ransom(self):
        # TODO:
        pid = None
        cmdline = None
        program = None
        timestamp = None
        event.dispatch(event.EventCryptoRansom(
            pid, cmdline, program, timestamp))
