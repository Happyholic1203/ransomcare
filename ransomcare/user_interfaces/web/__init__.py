#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

logger = logging.getLogger(__name__)

ctx = {}  # ransomcare context: sniffer, engine, etc will be populated
app = Flask(__name__)
db = None  # to be initialized in `init`

def init():
    from .views.api import api
    app.register_blueprint(api, url_prefix='/api')

    db = SQLAlchemy(app)
    globals().update({'db': db})  # populate db

    import models  # populate metadata

    if not db.engine.table_names():
        logger.debug('Initializing DB')
        db.create_all()
