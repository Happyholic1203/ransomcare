#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from flask import Flask

logger = logging.getLogger(__name__)

ctx = {}  # ransomcare context: sniffer, engine, etc will be populated
app = Flask(__name__)

def init():
    logger.debug('Initializing Web UI...')
    from .views.api import api
    app.register_blueprint(api, url_prefix='/api')

    from ... import models  # populate metadata

    from ... import db

    if not db.engine.table_names():
        logger.debug('Initializing DB')
        models.Base.metadata.create_all(bind=db.engine)
