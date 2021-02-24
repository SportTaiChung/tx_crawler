# coding: utf-8
import asyncio
import signal
from tx import TXCrawler
from logger import init_logger


class CrawlerRunner:

    def __init__(self, config, tasks, daemon=False):
        self._daemon = daemon
        self._config = config
        self._tasks = tasks
        self._config['_running'] = True
        self._loop = asyncio.get_event_loop()
        self._session_pool = None
        self._mq = None
        self._crawler = None
        self._crawler_tasks = []
        self._sport_info_map = None
        self._task_coro_id_crawler_map = {}
        self._closing = False
        self._logger_factory = init_logger

    def run(self):
        crawlers = []
        task_info = {}
        self._mq = asyncio.Queue()
        for task in self._tasks:
            crawler = TXCrawler(task, self._config)
            crawler.set_logger_factory(self._logger_factory)
            crawlers.append(crawler)
        for crawler in crawlers:
            crawler_task = self._loop.create_task(crawler.run(None, task_info, self._mq))
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
                        crawler_task = self._loop.create_task(crawler.run(None, {}, self._mq))
                        self._crawler_tasks[idx] = crawler_task
                        await crawler.logger.warning('重啟任務')
                        self._task_coro_id_crawler_map[id(crawler_task)] = crawler
                        del self._task_coro_id_crawler_map[id(task)]
                await asyncio.sleep(wait_time)

    def gracefully_stop(self):
        if not self._closing:
            self._closing = True
            self._loop.create_task(self.watch_dog_task(wait_time=0, stop=True))
