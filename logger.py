# -*- coding: utf-8 -*-
import time
from datetime import datetime
import logging
import asyncio
import aiohttp
from typing import Union
from aiologger.loggers.json import JsonLogger
from aiologger.utils import CallableWrapper
from aiologger.formatters.json import (FUNCTION_NAME_FIELDNAME,
                                       LOGGED_AT_FIELDNAME)
from aiologger.utils import loop_compat
from aiologger.filters import Filter
from aiologger.formatters.base import Formatter
from aiologger.handlers.base import Handler
from aiologger.levels import LogLevel
from aiologger.records import LogRecord


@loop_compat
class AsyncTelegramHandler(Handler):
    terminator = "\n"

    def __init__(
        self,
        session=None,
        config=None,
        level: Union[str, int, LogLevel] = LogLevel.NOTSET,
        formatter: Formatter = None,
        custom_filter: Filter = None
    ) -> None:
        super().__init__()
        if session is None:
            session = aiohttp.ClientSession()
        self.session = session
        self.config = config
        self.send_message_url = f"https://api.telegram.org/bot{config['telegram_token']}/sendMessage"
        self.level = level
        if formatter is None:
            formatter = Formatter()
        self.formatter: Formatter = formatter
        self.filter = custom_filter
        if self.filter:
            self.add_filter(self.filter)
        else:
            self.filter = Filter()
        self._initialization_lock = asyncio.Lock()

    @property
    def initialized(self):
        return self.session is not None

    async def handle(self, record: LogRecord) -> bool:
        rv = self.filter(record)
        if rv:
            await self.emit(record)
        return rv

    async def flush(self, message=None):
        await self.session.post(self.send_message_url, data={
            'chat_id': self.config['chat_id'],
            'text': message
        })

    async def emit(self, record: LogRecord):
        try:
            msg = self.formatter.format(record) + self.terminator
            await self.flush(message=msg)
        except Exception as exc:
            await self.handle_error(record, exc)

    async def close(self):
        if self.session is None:
            return
        await self.session.close()


def init_logger(name, extra=None):
    extra_keys = {
        'name': name,
        '@timestamp': CallableWrapper(time.time),
        '@datetime': CallableWrapper(datetime.now)
    }
    if extra is not None:
        extra_keys = {
            'name': name,
            **extra,
            '@timestamp': CallableWrapper(time.time),
            '@datetime': CallableWrapper(datetime.now)
        }
    logger = JsonLogger.with_default_handlers(
        name=name,
        level=logging.INFO,
        serializer_kwargs={'ensure_ascii': False},
        flatten=True,
        extra=extra_keys,
        exclude_fields=[
            FUNCTION_NAME_FIELDNAME, LOGGED_AT_FIELDNAME, 'file_path',
            'line_number'
        ])
    return logger
