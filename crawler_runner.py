# coding: utf-8
import asyncio
from asyncio.tasks import current_task
import signal
from collections import defaultdict
from copy import deepcopy
from tx import TXCrawler
from constants import TX
from logger import init_logger


class CrawlerRunner:

    def __init__(self, config, tasks, daemon=False):
        self._daemon = daemon
        self._config = config
        self._tasks = tasks
        self._config['_running'] = True
        self._loop = asyncio.get_event_loop()
        self._session_pool = None
        self._crawler = None
        self._crawler_tasks = []
        self._sport_info_map = None
        self._task_coro_id_crawler_map = {}
        self._closing = False
        self._logger_factory = init_logger

    def run(self):
        crawlers = []
        task_info = {}
        mq = asyncio.Queue
        for task in self._tasks:
            crawler = TXCrawler(task, self._config)
            crawler.set_logger_factory(self._logger_factory)
            crawlers.append(crawler)
        for crawler in crawlers:
            crawler_task = self._loop.create_task(crawler.run(None, task_info, mq))
            self._task_coro_id_crawler_map[id(crawler_task)] = crawler
            self._crawler_tasks.append(crawler_task)
        if not self._daemon:
            self._loop.create_task(self.watch_dog_task(stop=True))
        else:
            self._loop.create_task(self.watch_dog_task())
        self._loop.add_signal_handler(signal.SIGTERM, self.gracefully_stop)
        self._loop.add_signal_handler(signal.SIGINT, self.gracefully_stop)
        self._loop.run_forever()
        self._loop.close()

    async def session_manager(self):
        enabled_accounts = {}
        for account, account_info in self._config['accounts'].items():
            if account_info['enabled']:
                enabled_accounts[account] = account_info

    async def sport_task_manager(self, sport_type, tasks, mq):
        crawler_id_map = {}
        task_info_map = defaultdict(dict)
        task_key_map = {}
        task_crawler_map = defaultdict(list)
        task_mq_map = {}
        for task in tasks:
            crawler = TXCrawler(task, self._config)
            crawler.set_logger_factory(self._logger_factory)
            session = self._session_pool.get()
            task_key = f'{task["period"]}_{task["category"]}'
            task_key_map[task_key] = task
            task_mq = asyncio.Queue()
            crawler_task = self._loop.create_task(crawler.run(session, task_info_map[task_key], task_mq))
            task_mq_map[id(crawler_task)] = task_mq
            task_crawler_map[task_key].append(crawler_task)
            crawler_id_map[id(crawler_task)] = crawler
        while self._config['_running']:
            sport_info = self._sport_info_map[sport_type]
            for task_key, task_info in task_info_map.items():
                task = task_key_map[task_key]
                page_count = task_info[TX.Key.PageTotalRecord]
                # 爬蟲數量少於頁數
                current_crawler_num = len(task_crawler_map[task_key])
                if page_count > current_crawler_num:
                    for page_num in range(page_count + 1, current_crawler_num):
                        task_by_page = deepcopy(task)
                        task_by_page['page'] = page_num
                        crawler = TXCrawler(task_by_page, self._config)
                        crawler.set_logger_factory(self._logger_factory)
                        session = self._session_pool.get()
                        task_mq = asyncio.Queue()
                        crawler_task = self._loop.create_task(crawler.run(session, task_info_map[task_key], task_mq))
                        task_mq_map[id(crawler_task)] = task_mq
                        task_crawler_map[task_key].append(crawler_task)
                        crawler_id_map[id(crawler_task)] = crawler
                # 爬蟲數量多於頁數
                elif page_count < current_crawler_num:
                    for crawler_task in task_crawler_map[task_key][1:page_count]:
                        mq = task_mq_map[id(crawler_task)]
                        await mq.put({'action': 'shutdown'})
                        del task_mq_map[id(crawler_task)]
                        crawler = crawler_id_map[id(crawler_task)]
                        self._session_pool.recycle(crawler.get_session(), crawler.get_session_info)
            await asyncio.sleep(5)

    async def watch_dog_task(self, wait_time=30, stop=False):
        if wait_time > 0:
            await asyncio.sleep(wait_time)
        if stop and self._config['_running']:
            # stop crawlers
            self._config['_running'] = False
            while not all(task.done() for task in self._crawler_tasks):
                await asyncio.sleep(5)
            self._loop.stop()
        else:
            # watch and restart failed tasks
            while self._config['_running']:
                for idx, task in enumerate(self._crawler_tasks):
                    if task.done():
                        crawler = self._task_coro_id_crawler_map[id(task)]
                        crawler_task = self._loop.create_task(crawler.run())
                        self._crawler_tasks[idx] = crawler_task
                        await crawler.logger.warning('重啟任務')
                        self._task_coro_id_crawler_map[id(crawler_task)] = crawler
                        del self._task_coro_id_crawler_map[id(task)]
                await asyncio.sleep(wait_time)

    def gracefully_stop(self):
        if not self._closing:
            self._closing = True
            self._loop.create_task(self.watch_dog_task(wait_time=0, stop=True))
