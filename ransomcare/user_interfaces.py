#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import logging
import psutil

from . import event

logger = logging.getLogger(__name__)


class UI(object):
    def on_ask_user_allow_or_deny(self, evt):
        raise NotImplementedError()


class ConsoleUI(UI):
    def on_ask_user_allow_or_deny(self, evt):
        try:
            exe = evt.process.exe()
            cmdline = evt.process.cmdline()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.warn('Ransomware process is caught, but the process does '
                         'not exist (PID: %d)' % evt.pid)

        logger.critical('\033[91m')
        logger.critical('*** [Crypto ransom detected] ***')
        logger.critical('[PID]: %d' % evt.process.pid)
        logger.critical('[EXE]: %r' % exe)
        logger.critical('[Command]: %r' % cmdline)
        logger.critical('[File]: %s' % evt.path)
        logger.critical('********************************\033[0m')
        yes_no = raw_input('> Block it? (Y/n) ')

        allow = 'n' in yes_no.lower()
        if allow:
            event.dispatch(event.EventUserAllowProcess(evt.process))
        else:
            event.dispatch(event.EventUserDenyProcess(evt.process))


class WebUI(UI):
    def on_ask_user_allow_or_deny(self, evt):
        pass


class DarwinAppUI(UI):
    def on_ask_user_allow_or_deny(self, evt):
        pass
