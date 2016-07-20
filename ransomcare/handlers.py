#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import json

import psutil

from . import event

logger = logging.getLogger(__name__)


class Handler(object):
    def on_crypto_ransom(self, evt):
        raise NotImplementedError()

    def allow(self, exe):
        raise NotImplementedError()

    def deny(self, exe):
        raise NotImplementedError()


class WhiteListHandler(Handler, event.EventHandler):
    def __init__(self):
        event.EventHandler.__init__(self)
        self.whitelist = []  # exes (TODO: persist to a file)
        self.suspended = []  # processes

    @event.EventCryptoRansom.register_handler
    def on_crypto_ransom(self, evt):
        logger.debug('Whitelist: %s' % json.dumps(self.whitelist, indent=4))
        logger.debug('Suspended: %s' % json.dumps([
            {'pid': p.pid, 'exe': p.exe()} for p in self.suspended
        ], indent=4))
        if any(suspended.pid == evt.pid for suspended in self.suspended):
            return  # ignore captured ransom events

        try:
            p = psutil.Process(evt.pid)
            cmdline = p.cmdline()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.warn('Suspicious process %d exited before being caught'
                        % evt.pid)
            return

        if cmdline not in self.whitelist:
            p.suspend()
            self.suspended.append(p)
            event.EventAskUserAllowOrDeny(p, evt.path).fire()
        else:
            logger.info('Allowed white-listed process: %d' % evt.pid)

    @event.EventUserAllowProcess.register_handler
    def on_user_allow_process(self, evt):
        self.whitelist.append(evt.process.cmdline())
        for p in self.suspended:
            if p.pid == evt.process.pid:
                logger.info('Resuming PID %d (%s)' %
                            (p.pid, evt.process.cmdline()))
                p.resume()
                self.suspended.remove(p)
                return

    @event.EventUserDenyProcess.register_handler
    def on_user_deny_process(self, evt):
        for p in self.suspended:
            if p.pid == evt.process.pid:
                logger.info('Killing PID %d (%s)' %
                            (p.pid, evt.process.cmdline()))
                p.kill()
                self.suspended.remove(p)
                try:
                    cmdline = evt.process.cmdline()
                except psutil.AccessDenied:
                    return
                if cmdline in self.whitelist:
                    self.whitelist.remove(cmdline)
                return
