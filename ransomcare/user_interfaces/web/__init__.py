#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import logging
import threading
import datetime
import urllib2

import psutil

from .. import UI

logger = logging.getLogger(__name__)


class WebUI(UI):
    '''
    Can be used to expose internal states such as engine, sniffer states.
    '''
    def __init__(self, engine=None, sniffer=None, host='localhost', port=8888):
        self.engine = engine
        self.sniffer = sniffer
        self.host = host
        self.port = port

        from .views import app
        from .views import ctx
        self.ctx = ctx
        self.ctx['engine'] = self.engine
        self.ctx['sniffer'] = self.sniffer
        self.ctx['events'] = []
        self.app = app

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
            self.app.run(host=self.host, port=self.port)
        except Exception:
            pass
        finally:
            logger.debug('Web UI exited successfully')

    def _start_in_new_thread(self):
        self.ui_thread = threading.Thread(target=self.start_app)
        self.ui_thread.daemon = True  # thread dies with the program
        self.ui_thread.start()
        return self.ui_thread

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
        self.ctx['events'].append({
            'pid': evt.pid,
            'path': evt.path,
            'cmdline': cmdline,
            'exe': exe,
            'timestamp': datetime.datetime.now().isoformat()
        })

    def on_ask_user_allow_or_deny(self, evt):
        pass
