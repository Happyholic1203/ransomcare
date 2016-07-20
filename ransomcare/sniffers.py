#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import subprocess
import json
import logging
import threading
import thread
import time
import signal

import psutil
import eventlet

from . import event

logger = logging.getLogger(__name__)
pid_cwd = {}


def get_absolute_path(event_raw):
    '''
    Keeps a cache of processes' cwds, in case that their events might come
    after they're terminated.
    '''
    pid = event_raw.get('pid')
    path = event_raw.get('path')
    if path and path[0] == '/':
        return os.path.realpath(path)

    cwd = None
    logger.debug('%r' % pid_cwd)
    try:
        process = psutil.Process(pid)
        cwd = process.cwd()
        pid_cwd[pid] = cwd  # cache every pid's cwd
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        cwd = pid_cwd.get(pid)
        if not cwd:
            return None

    return os.path.realpath(os.path.join(cwd, path))


def to_absolute(pid, fd, path):
    if not path:
        return None
    if path[0] == '/':
        return path
    try:
        process = psutil.Process(pid)
        cwd = process.cwd()
        pid_cwd[pid] = cwd  # cache every pid's cwd
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        cwd = pid_cwd.get(pid)
        if not cwd:
            return None

    return os.path.realpath(os.path.join(cwd, path))


class DTraceSniffer(object):
    '''
    Sniffs and generates file events:
        EventFileOpen (pid, path)
        EventListDir (pid, path)
        EventFileRead (pid, path, size)
        EventFileWrite (pid, path, size)
        EventFileUnlink (pid, path)
        EventFileClose (pid, path)

    The path generated from dtrace might be relative paths, sniffer is
    reponsible for translating them into absolute paths.
    '''
    def __init__(self):
        self._sniffer = None
        self._should_stop = False
        self.files = {}  # files[pid][fd] gives the filename
        self._sniffer_reader = None  # eventlet greenthread
        self._sniffer_output = eventlet.Queue()

    def read_sniffer(self):
        logger.info('Sniffer started')
        while True:
            try:
                line = self._sniffer.stdout.readline()
                event_raw = json.loads(line)
                self._sniffer_output.put(event_raw)
                eventlet.sleep(0)  # yield control to engine
            except ValueError:
                if line != '\n' and line != "''":
                    logger.warn('Failed to JSON-decode: "%r"' % line)
                continue
            except IOError:
                logger.debug('DTrace exited')
                break

    def start(self):
        logger.info('Starting sniffer...')
        logger.debug('Starting dtrace... excluding self pid: %d' % os.getpid())
        DEVNULL = open(os.devnull, 'wb')
        self._sniffer = subprocess.Popen(
            ['./ransomcare/sniffer', '-x', str(os.getpid())],
            stdout=subprocess.PIPE, stderr=DEVNULL, preexec_fn=os.setsid)
        self._sniffer_reader = eventlet.spawn(self.read_sniffer)
        while not self._should_stop:
            try:
                event_raw = self._sniffer_output.get()
            except KeyboardInterrupt:
                break

            action = event_raw.get('action')
            pid = event_raw.get('pid')
            fd = event_raw.get('fd')
            path = event_raw.get('path')

            if action == 'stop':
                continue

            if action == 'open':
                path = self.update_path(pid, fd, path)
                if not path:
                    continue
            elif action in ('close', 'unlink'):
                path = self.remove_path(pid, fd)
                if not path:
                    continue
            else:
                path = self.get_path(pid, fd)
                if not path:
                    continue

            size = event_raw.get('size')
            timestamp = event_raw.get('t')
            if action == 'open':
                event.EventFileOpen(timestamp, pid, path).fire()
            elif action == 'listdir':
                event.EventListDir(timestamp, pid, path).fire()
            elif action == 'read':
                event.EventFileRead(timestamp, pid, path, size).fire()
            elif action == 'write':
                event.EventFileWrite(timestamp, pid, path, size).fire()
            elif action == 'close':
                event.EventFileClose(timestamp, pid, path).fire()
            elif action == 'unlink':
                event.EventFileUnlink(timestamp, pid, path).fire()
        self._sniffer.terminate()
        self._should_stop = True
        logger.info('Sniffer stopped')

    def stop(self):
        if self._should_stop:
            return
        logger.info('Stopping sniffer...')
        self._should_stop = True
        self._sniffer_output.put({'action': 'stop'})

    def update_path(self, pid, fd, path):
        if not path:
            return None
        self.files.setdefault(pid, {})
        if path[0] != '/':
            abspath = to_absolute(pid, fd, path)
            if not abspath:
                return None
        else:
            abspath = path
        self.files[pid][fd] = abspath
        return abspath

    def remove_path(self, pid, fd):
        '''
        Removes the file path associated with (pid, fd)

        Args:
            pid (int)
            fd (int)

        Returns:
            string: absolute path to the file associated with (pid, fd)
        '''
        path = self.files.get(pid, {}).get(fd, None)
        if path:
            del self.files[pid][fd]
            if len(self.files[pid]) == 0:
                del self.files[pid]
        return path

    def get_path(self, pid, fd):
        return self.files.get(pid, {}).get(fd, None)
