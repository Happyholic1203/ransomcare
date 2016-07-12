#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import logging
import json
import threading
import time

from . import event

logger = logging.getLogger(__name__)


class Engine(object):
    '''
    Detection logic: Only those PIDs who have done "listdir" operations will
    be **tracked**. When a **tracked** PID tries to close/unlink a file whose
    path has been listed before, the engine will check if the file has been
    fully read/written.

    Fully read -> unlink: (NEW_FILE_TYPE) ransomware detected
    Fully read -> fully written -> close: (OVERWRITE_TYPE) ransomware detected

    Please keep in mind that when events arrive here, they **already**
    happened. So you might have a tracked file being read, while the file has
    already been deleted.
    '''
    def __init__(self):
        '''
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
                "last_seen": "2016 Jul 12 22:28:31"
            }
        }
        '''
        self.pid_profiles = {}
        self._cleaner_stop = False
        self.cleaner = threading.Thread(target=self.clean_loop)
        self.cleaner.daemon = True  # dies with the program

    def clean_loop(self):
        '''
        Cleans up garbage in brain so it will run faster.
        '''
        logger.debug('Brain cleaner started')
        while not self._cleaner_stop:
            # TODO
            logger.debug('Cleaning...')
            time.sleep(1)
        logger.debug('Brain cleaner stopped')

    def start_cleaner(self):
        logger.debug('Starting brain cleaner...')
        self.cleaner.start()
        return self.cleaner

    def stop_cleaner(self):
        logger.debug('Stopping brain.cleaner...')
        self._cleaner_stop = True

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

        p = evt.get_process()
        self.pid_profiles.update({
            evt.pid: {
                'cmdline': p and p.cmdline(),
                'listdirs': [evt.path],
                'files': {},
                'last_seen': evt.timestamp
            }
        })

    def on_file_read(self, evt):
        logger.debug('read: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        self.pid_profiles[evt.pid]['last_seen'] = evt.timestamp
        file_profile['read'] += evt.size

    def on_file_write(self, evt):
        logger.debug('write: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        self.pid_profiles[evt.pid]['last_seen'] = evt.timestamp
        file_profile['write'] += evt.size

    def on_file_unlink(self, evt):
        logger.debug('unlink: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        profile = self.pid_profiles[evt.pid]
        profile['last_seen'] = evt.timestamp
        if file_profile['read'] >= file_profile['size']:
            self.on_crypto_ransom(evt.pid, evt.path)
            return

        profile['files'].pop(evt.path)

    def on_file_close(self, evt):
        logger.debug('close: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        profile = self.pid_profiles[evt.pid]
        profile['last_seen'] = evt.timestamp
        if file_profile['read'] >= file_profile['size'] and \
                file_profile['write'] >= file_profile['size']:
            self.on_crypto_ransom(evt.pid, evt.path)
            return

        profile['files'].pop(evt.path)

    def on_crypto_ransom(self, pid, path):
        logger.debug('Crypto ransom event detected')
        logger.debug('PID profiles: \n%s' %
                     json.dumps(self.pid_profiles, indent=4))
        event.dispatch(event.EventCryptoRansom(pid, path))

    def _get_file_profile(self, pid, path):
        profile = self.pid_profiles.get(pid)
        if not profile:
            return None

        file_profile = profile['files'].get(path)
        return file_profile
