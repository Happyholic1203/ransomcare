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

from . import user_interfaces
from . import handlers
from . import sniffers
from . import event
from . import engine


def main():
    system = platform.platform().lower()
    if system.startswith('darwin'):
        sniffer = sniffers.DTraceSniffer()
    else:
        raise NotImplementedError('Ransomcare is not ready for %s, '
                                  'please help porting it!' % system)

    white_list_handler = handlers.WhiteListHandler()
    event.register_event_handler(
        event.EventCryptoRansom, white_list_handler.on_crypto_ransom)
    event.register_event_handler(
        event.EventUserAllowProcess, white_list_handler.on_user_allow_process)
    event.register_event_handler(
        event.EventUserDenyProcess, white_list_handler.on_user_deny_process)

    console_ui = user_interfaces.ConsoleUI()
    event.register_event_handler(
        event.EventAskUserAllowOrDeny, console_ui.on_ask_user_allow_or_deny)

    brain = engine.Engine()
    event.register_event_handler(
        event.EventFileOpen, brain.on_file_open)
    event.register_event_handler(
        event.EventListDir, brain.on_list_dir)
    event.register_event_handler(
        event.EventFileRead, brain.on_file_read)
    event.register_event_handler(
        event.EventFileWrite, brain.on_file_write)
    event.register_event_handler(
        event.EventFileUnlink, brain.on_file_unlink)
    event.register_event_handler(
        event.EventFileClose, brain.on_file_close)

    sniffer.start()
