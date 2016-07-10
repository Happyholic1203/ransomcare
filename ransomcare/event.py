#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import psutil

logger = logging.getLogger(__name__)


class Event(object):
    @classmethod
    def get_id(cls):
        return id(cls)

    def get_process(self):
        try:
            return psutil.Process(self.pid)
        except Exception:
            return None


# -----------------
# -  File events  -
# -----------------


class EventFileOpen(Event):
    def __init__(self, timestamp, pid, path):
        self.timestamp = timestamp
        self.pid = pid
        self.path = path


class EventListDir(Event):
    def __init__(self, timestamp, pid, path):
        self.timestamp = timestamp
        self.pid = pid
        self.path = path


class EventFileRead(Event):
    def __init__(self, timestamp, pid, path, size):
        self.timestamp = timestamp
        self.pid = pid
        self.path = path
        self.size = size


class EventFileWrite(Event):
    def __init__(self, timestamp, pid, path, size):
        self.timestamp = timestamp
        self.pid = pid
        self.path = path
        self.size = size


class EventFileUnlink(Event):
    def __init__(self, timestamp, pid, path):
        self.timestamp = timestamp
        self.pid = pid
        self.path = path


class EventFileClose(Event):
    def __init__(self, timestamp, pid, path):
        self.timestamp = timestamp
        self.pid = pid
        self.path = path


# -----------------
# -  User events  -
# -----------------


class EventCryptoRansom(Event):
    def __init__(self, pid, path):
        self.pid = pid
        self.path = path


class EventUserAllowExe(Event):
    def __init__(self, exe):
        self.exe = exe


class EventUserDenyExe(Event):
    def __init__(self, exe):
        self.exe = exe


# ----------------
# -  Exceptions  -
# ----------------


class EventNotFound(Exception):
    pass


class _Dispatcher(object):
    def __init__(self, all_events):
        self.event_handlers = {}
        for e in all_events:
            self.event_handlers[e.get_id()] = []

    def dispatch(self, event):
        self._assert_valid_event_cls(type(event))
        for handler in self.event_handlers[event.get_id()]:
            handler(event)

    def register_event_handler(self, event_cls, handler):
        self._assert_valid_event_cls(event_cls)
        self._assert_valid_handler(handler)
        self.event_handlers[event_cls.get_id()].append(handler)

    def _assert_valid_event_cls(self, event_cls):
        if not issubclass(event_cls, Event):
            raise TypeError()
        if event_cls.get_id() not in self.event_handlers.keys():
            raise EventNotFound('"%s" is not a valid event' %
                                event_cls.__name__)

    @staticmethod
    def _assert_valid_handler(handler):
        if not callable(handler):
            raise Exception('Handler "%s" is not callable' % handler.__name__)

_dispatcher = _Dispatcher(Event.__subclasses__())


def register_event_handler(event, handler):
    _dispatcher.register_event_handler(event, handler)


def dispatch(event):
    _dispatcher.dispatch(event)
