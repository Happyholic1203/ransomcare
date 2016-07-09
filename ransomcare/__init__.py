#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Yu-Cheng (Henry) Huang'

import logging

level = logging.DEBUG
logger = logging.getLogger(__name__)
logger.setLevel(level)
fmt = logging.Formatter('%(asctime)s %(name)s %(levelname)s: %(message)s')

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(fmt)
stream_handler.setLevel(level)
logger.addHandler(stream_handler)

import platform

from . import notifiers
from . import sniffers
from . import event
from . import engine


def main():
    _platform = platform.platform().lower()
    if _platform.startswith('darwin'):
        _sniffer = sniffers.DTraceSniffer()
    else:
        raise NotImplementedError('Ransomcare is not ready for %s, '
                                  'please help porting it!' % _platform)

    _log_notifier = notifiers.LogNotifier()
    event.register_event_handler(
        event.EventCryptoRansom, _log_notifier.on_crypto_ransom)

    _engine = engine.Engine()
    event.register_event_handler(
        event.EventFileOpen, _engine.on_file_open)
    event.register_event_handler(
        event.EventListDir, _engine.on_list_dir)
    event.register_event_handler(
        event.EventFileRead, _engine.on_file_read)
    event.register_event_handler(
        event.EventFileWrite, _engine.on_file_write)
    event.register_event_handler(
        event.EventFileUnlink, _engine.on_file_unlink)
    event.register_event_handler(
        event.EventFileClose, _engine.on_file_close)

    _sniffer.start()
