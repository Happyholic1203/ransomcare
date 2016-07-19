#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Yu-Cheng (Henry) Huang'

import logging

logger = logging.getLogger(__name__)

import platform
import time

from . import user_interfaces
from . import handlers
from . import sniffers
from . import event
from . import engine


def _init_logging(level, log_stream=True, log_file=None):
    logger.setLevel(level)
    fmt = logging.Formatter('%(asctime)s %(name)s %(levelname)s: %(message)s')

    if log_stream:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(fmt)
        stream_handler.setLevel(level)
        logger.addHandler(stream_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(fmt)
        file_handler.setLevel(level)
        logger.addHandler(file_handler)


def main(log_level=logging.DEBUG, log_stream=True, log_file=None):
    """
          [Sniffer]
              |
              |
         file events
              |
              |
              v
          [Engine] --------------------+
              |                        |
              |                        |
         ransom events -----+          |
              |             |          |
              v             |     suspicious
          [Handler]         |     processes
          |      ^          |          |
        allow?   |          |          |
          |   response      |          |
          v      |          |          |
          [  UI  ] <--------+----------+
    """

    _init_logging(level=log_level, log_stream=log_stream)

    system = platform.platform().lower()
    if system.startswith('darwin'):
        sniffer = sniffers.DTraceSniffer()
    else:
        raise NotImplementedError('Ransomcare is not ready for %s, '
                                  'please help porting it!' % system)

    white_list_handler = handlers.WhiteListHandler()  # handles ransom events
    white_list_handler.start()

    # passes user responses -> handler
    console_ui = user_interfaces.ConsoleUI()
    console_ui.start()

    brain = engine.Engine()  # generates user events -> UI
    brain.start()

    web_ui = user_interfaces.WebUI(
        engine=brain, sniffer=sniffer)
    web_ui.start()

    sniffer.start()  # main loop: generates file events -> brain

    logger.debug('Cleaning up everything...')

    sniffer.stop()
    web_ui.stop()
    white_list_handler.stop()
    console_ui.stop()
    brain.stop()

    logger.debug('Everything cleaned up successfully, exiting...')
