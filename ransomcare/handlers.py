#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import psutil

logger = logging.getLogger(__name__)


class Handler(object):
    def on_crypto_ransom(self, evt):
        raise NotImplementedError()

    def allow(self, exe):
        raise NotImplementedError()

    def deny(self, exe):
        raise NotImplementedError()


class WhiteListHandler(Handler):
    def __init__(self):
        self.whitelist = []  # TODO: persist to a file
        self.suspended = []

    def on_crypto_ransom(self, evt):
        try:
            p = psutil.Process(evt.pid)
            exe = p.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.warn('Suspicious process %d exited before being caught'
                            % evt.pid)
            return
        if exe not in self.whitelist:
            p.suspend()
            self.suspended.append(p)
        else:
            logger.info('Allowed white-listed process: %d' % evt.pid)

    def on_user_allow_exe(self, evt):
        self.whitelist.append(evt.exe)
        for p in self.suspended:
            if p.exe() == evt.exe:
                logger.info('Resuming PID %d (%s)' % (p.pid, evt.exe))
                p.resume()
                self.suspended.remove(p)
                return

    def on_user_deny_exe(self, evt):
        for p in self.suspended:
            if p.exe() == evt.exe:
                logger.info('Killing PID %d (%s)' % (p.pid, evt.exe))
                p.kill()
                self.suspended.remove(p)
                if evt.exe in self.whitelist:
                    self.whitelist.remove(evt.exe)
                return
