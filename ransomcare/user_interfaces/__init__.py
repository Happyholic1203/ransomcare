#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import urllib2
import threading
import datetime
import eventlet
import eventlet.wsgi
import time

import psutil

from .. import event

logger = logging.getLogger(__name__)


class UI(object):
    def on_ask_user_allow_or_deny(self, evt):
        raise NotImplementedError()


class WebUI(UI, event.EventHandler):
    '''
    Can be used to expose internal states such as engine, sniffer states.
    '''
    def __init__(self, engine=None, sniffer=None, host='localhost', port=8888):
        event.EventHandler.__init__(self)
        self.engine = engine
        self.sniffer = sniffer
        self.host = host
        self.port = port
        self.ui_thread = threading.Thread(target=self.start_app)
        self.ui_thread.daemon = True  # thread dies with the program

        from . import web
        self.web = web
        self.web.ctx['engine'] = self.engine
        self.web.ctx['sniffer'] = self.sniffer
        self.web.ctx['events'] = []

        from .. import config
        self.web.app.config.from_object(config)
        self.web.init()

    def start(self):
        logger.info('Starting Web UI...')
        event.EventHandler.start(self)
        t = self._start_in_new_thread()
        logger.info('Web UI started')
        return t

    def stop(self):
        logger.info('Stopping Web UI...')
        self.server_thread.close()
        logger.info('Web UI stopped')

    def start_app(self):
        try:
            self.server_thread = eventlet.listen((self.host, self.port))
            eventlet.wsgi.server(self.server_thread, self.web.app)
        except Exception as e:
            logger.exception(e)

    def _start_in_new_thread(self):
        self.ui_thread.start()
        return self.ui_thread

    @event.EventCryptoRansom.register_handler
    def on_crypto_ransom(self, evt):
        logger.debug('Got crypto ransom event')
        cmdline, exe = None, None
        try:
            p = psutil.Process(evt.pid)
            cmdline = p.cmdline()
            exe = p.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pid_profile = self.engine.pid_profiles.get(evt.pid)
            if pid_profile is not None:
                cmdline = pid_profile.get('cmdline')
                exe = cmdline[0] if cmdline else None
        crypto_ransom_event = {
            'pid': evt.pid,
            'path': evt.path,
            'cmdline': cmdline,
            'exe': exe,
            'timestamp': datetime.datetime.now().isoformat()
        }
        self.web.ctx['events'].append(crypto_ransom_event)
        self.web.socketio.emit('event', crypto_ransom_event)

    @event.EventAskUserAllowOrDeny.register_handler
    def on_ask_user_allow_or_deny(self, evt):
        self.web.socketio.emit('prompt', {
            'id': 'KILL_OR_NOT',
            'message': ('PID %d seems to be encrypting %s Kill it?' %
                        (evt.process.pid, evt.path)),
            'data': {
                'pid': evt.process.pid,
                'path': evt.path,
                'cmdline': evt.process.cmdline()
            }
        })

from .console import ConsoleUI
from .darwin import DarwinAppUI
