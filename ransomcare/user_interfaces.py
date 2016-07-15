#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import logging
import threading
import json
import datetime
import urllib2

import psutil
from flask import Flask, request

from . import event

logger = logging.getLogger(__name__)


class UI(object):
    def on_ask_user_allow_or_deny(self, evt):
        raise NotImplementedError()


def flush_stdin():
    try:
        import termios  # linux
        termios.tcflush(sys.stdin, termios.TCIOFLUSH)
    except ImportError:
        import msvcrt  # windows
        while msvcrt.kbhit():
            msvcrt.getch()


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
        flush_stdin()
        yes_no = raw_input('> Block it? (Y/n) ')

        allow = 'n' in yes_no.lower()
        if allow:
            event.dispatch(event.EventUserAllowProcess(evt.process))
        else:
            event.dispatch(event.EventUserDenyProcess(evt.process))


class WebUI(UI):
    '''
    Can be used to expose internal states such as engine, sniffer states.
    '''
    def __init__(self, engine=None, sniffer=None, host='localhost', port=8888):
        self.engine = engine
        self.sniffer = sniffer
        self.host = host
        self.port = port

        self.ransom_events = []

        self.app = Flask(__name__)
        self.init_routes()

    def start(self):
        return self._start_in_new_thread()

    def stop(self):
        logger.debug('Stopping Web UI...')
        skt = {'host': self.host, 'port': self.port}
        try:
            url = 'http://{host}:{port}/shutdown'.format(**skt)
            logger.debug('Stopping by HTTP GET: %s' % url)
            r = urllib2.urlopen(url, timeout=5)
            r.read()
            r.close()
        except IOError:
            return
        except Exception as e:
            logger.exception(e)
            return

    def _start_in_new_thread(self):
        def start_app():
            try:
                self.app.run(host=self.host, port=self.port)
            except Exception:
                pass
            finally:
                logger.debug('Web UI exited successfully')
        t = threading.Thread(target=start_app)
        t.daemon = True  # thread dies with the program
        t.start()
        return t

    def init_routes(self):
        app = self.app
        @app.route('/')
        def dashboard():
            return 'dashboard'

        @app.route('/shutdown')
        def shutdown():
            shutdown_func = request.environ.get('werkzeug.server.shutdown')
            if shutdown_func is None:
                raise RuntimeError('Not running with Werkzeug server')
            # TODO: shutdown sniffer
            shutdown_func()
            return ''

        @app.route('/engine')
        def engine():
            return json.dumps(self.engine.pid_profiles, indent=2)

        @app.route('/ransom_events')
        def ransom_events():
            return json.dumps(self.ransom_events, indent=2)

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
        self.ransom_events.append({
            'pid': evt.pid,
            'path': evt.path,
            'cmdline': cmdline,
            'exe': exe,
            'timestamp': datetime.datetime.now().isoformat()
        })

    def on_ask_user_allow_or_deny(self, evt):
        pass


class DarwinAppUI(UI):
    def on_ask_user_allow_or_deny(self, evt):
        pass
