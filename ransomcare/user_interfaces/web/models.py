#!/usr/bin/env python
# -*- coding: utf-8 -*-

from . import db


class BenignProgram(db.Model):

    """A BegignProgram will bypass sniffer and will never be detected"""

    __tablename__ = 'benign_program'

    id = db.Column(db.Integer, primary_key=True)
    cmdline = db.Column(db.String(512), unique=True, nullable=False)
    added_at = db.Column(db.Date)
