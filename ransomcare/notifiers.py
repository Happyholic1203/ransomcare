#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function


class LogNotifier(object):
    def on_crypto_ransom(self, event):
        print('*** Crypto ransom detected!')
