#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Yu-Cheng (Henry) Huang'

import logging

logger = logging.getLogger(__name__)

import platform

from . import config
from . import user_interfaces
from . import handlers
from . import sniffers
from . import engine


def _init_logging(level, log_stream=True, log_file=None):
    logger.setLevel(config.LOG_LEVEL)
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

    # generates user events -> UI
    brain = engine.Engine()
    brain.start()

    # passes user responses -> handler
    web_ui = user_interfaces.WebUI(
        engine=brain, sniffer=sniffer)
    web_ui.start()

    # main loop: generates file events -> brain
    sniffer.start()

    logger.info('Cleaning up everything...')

    sniffer.stop()
    web_ui.stop()
    white_list_handler.stop()
    brain.stop()

    logger.info('Everything cleaned up successfully, exiting...')
