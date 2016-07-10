#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import logging
import psutil

from . import event

logger = logging.getLogger(__name__)


class UI(object):
    def on_crypto_ransom(self, evt):
        raise NotImplementedError()


class ConsoleUI(UI):
    def on_crypto_ransom(self, evt):
        exe = None
        p = None
        try:
            p = psutil.Process(evt.pid)
            exe = p.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.warn('Ransomware process is caught, but the process does '
                         'not exist (PID: %d)' % evt.pid)
            return

        logger.critical('\033[91m')
        logger.critical('*** [Crypto ransom detected] ***')
        logger.critical('[PID]: %d' % evt.pid)
        logger.critical('[EXE]: %r' % exe)
        logger.critical('[Command]: %r' % p.cmdline())
        logger.critical('[File]: %s' % evt.path)
        logger.critical('********************************\033[0m')
        yes_no = raw_input('> Block it? (Y/n) ')

        allow = 'n' in yes_no.lower()
        if allow:
            event.dispatch(event.EventUserAllowExe(exe))
        else:
            event.dispatch(event.EventUserDenyExe(exe))


class WebUI(UI):
    def on_crypto_ransom(self, evt):
        pass


class DarwinAppUI(UI):
    def on_crypto_ransom(self, evt):
        pass
