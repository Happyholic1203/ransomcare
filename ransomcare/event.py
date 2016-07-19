#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import Queue
import threading
import inspect

import psutil

logger = logging.getLogger(__name__)


def _is_event_handler(method):
    return hasattr(method, 'evt_cls')


# Singleton
class EventHandler(object):
    def __init__(self):
        cls = type(self)
        if hasattr(cls, 'has_instance'):
            raise Exception('An event handler should have at most one '
                            'instance')
        cls.has_instance = True

        cls.handlers = {}  # event class -> handler method
        cls.events = Queue.Queue()

        self._is_active = False
        self._handler_thread = threading.Thread(target=self._event_loop)
        self._handler_thread.daemon = True

        class EventStop(Event):
            pass

        self._evt_stop = EventStop()

        self.register_event_handlers()

    def start(self):
        self._is_active = True
        self._handler_thread.start()

    def stop(self):
        self._is_active = False
        cls = type(self)
        cls.events.put(self._evt_stop)
        self._handler_thread.join()

    def register_event_handlers(self):
        for _, method in inspect.getmembers(self, inspect.ismethod):
            if _is_event_handler(method):
                self.register_handler(method.evt_cls, method)

    def register_handler(self, evt_cls, method):
        """Registers the `evt_cls` -> `method` mapping in handler. Registers
        this handler's event queue to `evt_cls`, so this type of events will
        be dispatched to this handler.
        """
        cls = type(self)
        cls.handlers.setdefault(evt_cls, set())
        cls.handlers[evt_cls].add(method)
        evt_cls.handler_event_queues.add(self.events)

    def _event_loop(self):
        cls = type(self)
        while self._is_active:
            try:
                evt = cls.events.get()
            except Exception as e:
                logger.exception(e)
                continue
            if evt == self._evt_stop:
                logger.debug('Got EventStop')
                continue
            evt_cls = type(evt)
            # locate the handler method
            handlers = cls.handlers.get(evt_cls)
            if not handlers:
                raise Exception('%s did not register event: %s' %
                                (cls.__name__, evt_cls.__name__))
            # invoke the handler method
            for handler in handlers:
                handler(evt)
        print('event loop done')


class EventMeta(type):
    def __init__(self, name, bases, attrs):
        self.handler_event_queues = set()
        return super(EventMeta, self).__init__(name, bases, attrs)


class Event(object):
    __metaclass__ = EventMeta

    def fire(self):
        """Puts itself into all handlers' :attr:`events` (event queue). Each
        :class:`EventHandler` instance should have its own running thread to
        handle those events.
        """
        for event_queue in type(self).handler_event_queues:
            event_queue.put(self)

    @classmethod
    def register_handler(cls, handler):
        """When this event fires, this event enques itself into :attr:`events`
        of :class:`EventHandler`.

        Args:
            handler_method: a method of an :class:`EventHandler` instance

        Returns:
            the original handler function

        Exceptions:
            TypeError: when the handler is not of type :class:`EventHandler`
        """
        handler.evt_cls = cls
        return handler


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


class EventAskUserAllowOrDeny(Event):
    def __init__(self, process, path):
        self.process = process
        self.path = path


class EventUserAllowProcess(Event):
    def __init__(self, process):
        self.process = process


class EventUserDenyProcess(Event):
    def __init__(self, process):
        self.process = process


# ----------------
# -  Exceptions  -
# ----------------


class EventNotFound(Exception):
    pass
