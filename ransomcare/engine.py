#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import eventlet
eventlet.monkey_patch()

import os
import logging
import json
from datetime import datetime, timedelta

import psutil

from . import event

logger = logging.getLogger(__name__)


def get_process(pid):
    try:
        return psutil.Process(pid)
    except Exception:
        return None


def is_alive(pid):
    try:
        return get_process(pid).is_running()
    except Exception:
        return False


class Engine(event.EventHandler):
    """Detection logic: Only those PIDs who have done "listdir" operations will
    be **tracked**. When a **tracked** PID tries to close/unlink a file whose
    path has been listed before, the engine will check if the file has been
    fully read/written.

    Fully read -> unlink: (NEW_FILE_TYPE) ransomware detected
    Fully read -> fully written -> close: (OVERWRITE_TYPE) ransomware detected

    Please keep in mind that when events arrive here, they **already**
    happened. So you might have a tracked file being read, while the file has
    already been deleted.

    The engine keeps the following data structure::
        self.pid_profiles = {
            pid: {
                "cmdline": "xxx -a -b",  # command line string
                "listdirs": ["dir1", "dir2"],  # dirs listed by `pid`
                "files": {  # list only files under "listdirs"
                    "file1": {
                        "size": 100,  # size in bytes
                        "read": 100,  # bytes read
                        "write": 100  # bytes written
                    }
                },
                "last_seen": "2016 Jul 12 22:28:31",
                "read": 1382,  # bytes read from all victim files
                "write": 1492  # bytes written since first victim file is read
            }
        }
    """
    def __init__(self):
        super(Engine, self).__init__(privileged=True)
        self.pid_profiles = {}
        self._cleaner_thread = None
        self._cleaner_stop = False

    def start(self):
        logger.info('Starting engine...')
        super(Engine, self).start()
        self._start_cleaner()
        logger.info('Engine started')

    def stop(self):
        logger.info('Stopping engine...')
        super(Engine, self).stop()
        self._stop_cleaner()
        logger.info('Engine stopped')

    def _clean_loop(self):
        '''
        Cleans up garbage in brain so it will run faster.
        '''
        logger.info('Cleaner started')
        fmt = '%Y %b %d %H:%M:%S'
        period_seconds = 2
        obselete_seconds = 10
        while not self._cleaner_stop:
            obselete_pids = []
            long_ago = datetime.now() - timedelta(seconds=obselete_seconds)
            for pid, profile in self.pid_profiles.iteritems():
                last_seen = datetime.strptime(
                    profile['last_seen'], fmt)
                if last_seen <= long_ago and not is_alive(pid):
                    obselete_pids.append(pid)
            if obselete_pids:
                logger.debug('Cleaning obselete pids: %r...' % obselete_pids)
                for obselete_pid in obselete_pids:
                    try:
                        del self.pid_profiles[obselete_pid]
                    except KeyError:
                        pass
            eventlet.sleep(period_seconds)
        logger.info('Cleaner stopped')

    def _start_cleaner(self):
        logger.info('Starting cleaner...')
        self._cleaner_thread = eventlet.spawn(self._clean_loop)

    def _stop_cleaner(self):
        logger.info('Stopping cleaner...')
        self._cleaner_stop = True

    @event.EventFileOpen.register_handler
    def on_file_open(self, evt):
        logger.debug('open: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))
        profile = self.pid_profiles.get(evt.pid)
        if not profile:
            return

        profile['last_seen'] = evt.timestamp
        if os.path.isdir(evt.path):
            return

        for d in profile['listdirs']:
            parent_dir = os.path.abspath(os.path.join(evt.path, '..'))
            if parent_dir == d:
                if evt.path not in profile['files']:
                    logger.debug('\033[93mPossible victim file: %s\033[0m' %
                                 evt.path)
                    try:
                        size = os.stat(evt.path).st_size
                    except Exception:
                        size = -1  # file does not exist or is unlinked

                    # ignore empty files, otherwise they'll be reported
                    # immediately
                    if size != 0:
                        profile['files'][evt.path] = {
                            'size': size,
                            'read': 0,
                            'write': 0
                        }
                break

    @event.EventListDir.register_handler
    def on_list_dir(self, evt):
        logger.debug('listdir: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))
        pid_profile = self.pid_profiles.get(evt.pid)
        if pid_profile:
            pid_profile['last_seen'] = evt.timestamp
            listdirs = pid_profile['listdirs']
            if evt.path not in listdirs:
                listdirs.append(evt.path)
            return

        p = get_process(evt.pid)
        try:
            cmdline = p and p.cmdline()
        except Exception:
            cmdline = '(Process exited)'
        self.pid_profiles.update({
            evt.pid: {
                'cmdline': cmdline,
                'listdirs': [evt.path],
                'files': {},
                'last_seen': evt.timestamp,
                'read': 0,  # bytes read from all victim files
                'write': 0  # bytes written since first victim file is read
            }
        })

    @event.EventFileRead.register_handler
    def on_file_read(self, evt):
        logger.debug('read: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        pid_profile = self.pid_profiles[evt.pid]
        pid_profile['last_seen'] = evt.timestamp
        pid_profile['read'] += evt.size
        file_profile['read'] += evt.size

    @event.EventFileWrite.register_handler
    def on_file_write(self, evt):
        logger.debug('write: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        pid_profile = self.pid_profiles.get(evt.pid)
        if pid_profile and pid_profile['files']:
            # this suspicious process might have started writing encrypted
            # files: record the total bytes it has written
            pid_profile['write'] += evt.size

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        self.pid_profiles[evt.pid]['last_seen'] = evt.timestamp
        file_profile['write'] += evt.size

    @event.EventFileUnlink.register_handler
    def on_file_unlink(self, evt):
        logger.debug('unlink: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        pid_profile = self.pid_profiles[evt.pid]
        pid_profile['last_seen'] = evt.timestamp
        if file_profile['read'] >= file_profile['size'] and \
                pid_profile['write'] >= (pid_profile['read'] / 2):
            # TYPE_NEWFILE: Write encrypted data to a new file
            self.report_crypto_ransom(evt.pid, evt.path)
            return

        pid_profile['files'].pop(evt.path)

    @event.EventFileClose.register_handler
    def on_file_close(self, evt):
        logger.debug('close: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        pid_profile = self.pid_profiles[evt.pid]
        pid_profile['last_seen'] = evt.timestamp
        if file_profile['read'] > 0 and \
                file_profile['read'] >= file_profile['size'] and \
                file_profile['write'] >= file_profile['size'] and \
                pid_profile['write'] >= (pid_profile['read'] / 2):
            # TYPE_OVERWRITE: Overwrite with encrypted data
            self.report_crypto_ransom(evt.pid, evt.path)
            return

        pid_profile['files'].pop(evt.path)

    def report_crypto_ransom(self, pid, path):
        logger.info('Crypto ransom event detected')
        logger.debug('PID profiles: \n%s' %
                     json.dumps(self.pid_profiles, indent=4))
        event.EventCryptoRansom(pid, path).fire()

    def _get_file_profile(self, pid, path):
        profile = self.pid_profiles.get(pid)
        if not profile:
            return None

        file_profile = profile['files'].get(path)
        return file_profile
