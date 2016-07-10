#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import logging

from . import event

logger = logging.getLogger(__name__)


class Engine(object):
    '''
    Only those PIDs who have done "listdir" operations will be **tracked**.
    When a **tracked** PID tries to close/unlink a file whose path has been
    listed before, the engine will check if the file has been fully
    read/written.

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
                }
            }
        }
        '''
        self.pid_profiles = {}

    def on_file_open(self, evt):
        logger.debug('open: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))
        profile = self.pid_profiles.get(evt.pid)
        if not profile:
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
            listdirs = pid_profile['listdirs']
            if evt.path not in listdirs:
                listdirs.append(evt.path)
            return

        p = evt.get_process()
        self.pid_profiles.update({
            evt.pid: {
                'cmdline': p and p.cmdline(),
                'listdirs': [evt.path],
                'files': {}
            }
        })

    def on_file_read(self, evt):
        logger.debug('read: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        file_profile['read'] += evt.size

        # early alert: reading on a tracked file, which is already deleted
        if not os.path.exists(evt.path):
            self.on_crypto_ransom(evt.pid, evt.path)

    def on_file_write(self, evt):
        logger.debug('write: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        file_profile['write'] += evt.size

    def on_file_unlink(self, evt):
        logger.debug('unlink: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        if file_profile['read'] >= file_profile['size']:
            self.on_crypto_ransom(evt.pid, evt.path)

    def on_file_close(self, evt):
        logger.debug('close: %d (%s) -> %s' % (
            evt.pid, evt.timestamp, evt.path))

        file_profile = self._get_file_profile(evt.pid, evt.path)
        if not file_profile:
            return

        if file_profile['write'] >= file_profile['size']:
            self.on_crypto_ransom(evt.pid, evt.path)

    @staticmethod
    def on_crypto_ransom(pid, path):
        event.dispatch(event.EventCryptoRansom(pid, path))

    def _get_file_profile(self, pid, path):
        profile = self.pid_profiles.get(pid)
        if not profile:
            return None

        file_profile = profile['files'].get(path)
        return file_profile
