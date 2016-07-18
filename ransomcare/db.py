#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging

from sqlalchemy import create_engine
from sqlalchemy.orm.session import sessionmaker

from . import config

logger = logging.getLogger(__name__)

logger.debug('Initializing db engine: echo=%r' % config.SQLALCHEMY_ECHO)
engine = create_engine(config.SQLALCHEMY_DATABASE_URI,
                       echo=config.SQLALCHEMY_ECHO)
Session = sessionmaker(bind=engine)
session = Session()
