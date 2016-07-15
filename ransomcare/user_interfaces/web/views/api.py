#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import signal
import logging

from flask import request, Blueprint

from . import ctx

logger = logging.getLogger(__name__)
api = Blueprint('api', __name__)


@api.route('/shutdown')
def _shutdown():
    shutdown_func = request.environ.get('werkzeug.server.shutdown')
    if shutdown_func is None:
        raise RuntimeError('Not running with Werkzeug server')
    logger.debug('Shuting down flask...')
    shutdown_func()
    ctx['sniffer'].stop()  # shutdown main loop
    logger.debug('Flask down')
    return 'OK'


@api.route('/processes')
def engine():
    return json.dumps(ctx['engine'].pid_profiles, indent=2)


@api.route('/events')
def ransom_events():
    return json.dumps(ctx['events'], indent=2)
