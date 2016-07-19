#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import urllib2
import threading
import datetime

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
        return self._start_in_new_thread()

    def stop(self):
        logger.debug('Stopping Web UI...')
        skt = {'host': self.host, 'port': self.port}
        try:
            url = 'http://{host}:{port}/api/shutdown'.format(**skt)
            logger.debug('Stopping by HTTP GET: %s' % url)
            r = urllib2.urlopen(url, timeout=5)
            r.read()
            r.close()
        except IOError:
            pass
        except Exception as e:
            logger.exception(e)
        self.ui_thread.join()

    def start_app(self):
        try:
            self.web.app.run(host=self.host, port=self.port)
        except Exception as e:
            logger.exception(e)
        finally:
            logger.debug('Web UI exited successfully')

    def _start_in_new_thread(self):
        self.ui_thread.start()
        return self.ui_thread

    @event.EventCryptoRansom.register_handler
    def on_crypto_ransom(self, evt):
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
        self.web.ctx['events'].append({
            'pid': evt.pid,
            'path': evt.path,
            'cmdline': cmdline,
            'exe': exe,
            'timestamp': datetime.datetime.now().isoformat()
        })

    def on_ask_user_allow_or_deny(self, evt):
        pass

from .console import ConsoleUI
from .darwin import DarwinAppUI
