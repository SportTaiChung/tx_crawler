# -*- coding: utf-8 -*-
"""
ps38 crawler
"""

import asyncio
from json.decoder import JSONDecodeError
import os
import subprocess
from urllib.parse import urlencode
from datetime import datetime, timedelta
import logging
import uuid
import random
from functools import wraps
from itertools import cycle, product
import traceback
from time import perf_counter, time
from math import floor, hypot
from copy import deepcopy
from hashlib import md5
import hmac
import urllib.parse
from pyquery import PyQuery as pq
import base64
import xxtea
import re
import pickle
import aiohttp
import aiofiles
import aio_pika
from fake_useragent import UserAgent
import json
from google.protobuf import text_format
import APHDC_pb2 as protobuf_spec
from constants import *
from utils import split_upload_bulk
from logger import AsyncTelegramHandler


def step_logger(step_name):
    def decorator(f):
        @wraps(f)
        async def wrapped(self, *args, **kwargs):
            self.step_log_json.clear()
            self.step_log_json['execution_id'] = self.execution_id
            self.step_log_json['step'] = step_name
            self.step_log_json['ip'] = self.ip_addr
            start_time = time()
            result = None
            try:
                result = await f(self, *args, **kwargs)
            except Exception:
                self.task_failed = True
                self.step_log_json['fatal_exception'] = traceback.format_exc()
            end_time = time()
            process_time = end_time - start_time
            self.step_log_json['start_time'] = datetime.fromtimestamp(start_time).isoformat()
            self.step_log_json['end_time'] = datetime.fromtimestamp(end_time).isoformat()
            self.step_log_json['process_time'] = round(process_time, 3)
            failed_continue_1_min = self.last_success_time - datetime.now() > timedelta(minutes=1)
            if (self.task_failed and failed_continue_1_min) or self.step_log_json.get('exception') or self.step_log_json.get('error'):
                await self.logger.error(f"{self.account} {self.name} ????????????", extra=self.step_log_json)
            else:
                await self.logger.info('??????', extra=self.step_log_json)
            return result
        return wrapped
    return decorator


class TXCrawler:
    """Crawler implementation for ps38"""

    def __init__(self, tasks, secrets):
        super().__init__()
        self._tasks = tasks
        self.task_spec = None
        self.name = tasks[0]['crawler_name']
        self._config = secrets
        self.logger = None
        self._logger_factory = None
        self.step_log_json = {}
        self.mq_connection_pool = None
        self.mq_channel_pool = None
        self.execution_id = None
        self.last_execution_time = datetime.now()
        self.task_failed = False
        self.last_success_time = datetime.now()
        self.ip_addr = ''
        self._session = None
        self._session_info = None
        self.account_banned = False
        self.account = ''
        self.relogin_count = 0
        self.next_relogin_time = datetime.now()
        self.site_maintaining = False
        self._sport_info = None
        self._mq = None
        self.user_agent = UserAgent(fallback=DEFAULT_USER_AGENT)
        self.headers = self._config['login_headers']
        self._session_login_info_map = {}
        self.data = None
        self._zero_uszf = protobuf_spec.usZF(
            homeZF=protobuf_spec.typeZF(line='-0', odds='0'),
            awayZF=protobuf_spec.typeZF(line='+0', odds='0'),
        )
        self._zero_usds = protobuf_spec.typeDS(
            line='0',
            over='0',
            under='0'
        )
        self._zero_twzf = protobuf_spec.twZF(
            homeZF=protobuf_spec.typeZF(line='-0', odds='0'),
            awayZF=protobuf_spec.typeZF(line='+0', odds='0'),
        )
        self._zero_twds = protobuf_spec.typeDS(
            line='0',
            over='0',
            under='0'
        )
        self._zero_de = protobuf_spec.onetwo(home='0', away='0')
        self._zero_sd = protobuf_spec.onetwo(home='0', away='0')
        self._zero_esre = protobuf_spec.Esre(
            let=protobuf_spec.home,
            home='0',
            away='0'
        )

    def set_logger_factory(self, logger_factory):
        self._logger_factory = logger_factory('tx',
                                              extra={
                                                  'game_type': self._tasks[0]['game_type'],
                                                  'play_type': self._tasks[0]['period']
                                              })

    async def reset_session(self, session):
        try:
            sport_info = await self.query_sport_info(session)
            if sport_info:
                self._session = session
                return True
        except aiohttp.ClientError:
            await self.logger.error('??????????????????')
        return False

    async def run(self, session, task_info, mq):
        self.logger = self._logger_factory
        sessions = []
        if not self._config['read_from_file']:
            await self.init_mq()
            if self._config['debug'] and os.path.exists('saved_cookies.pickle'):
                with open('saved_cookies.pickle', 'rb') as session_file:
                    cookies = pickle.load(session_file, pickle.HIGHEST_PROTOCOL)
                    sessions = await self.init_session(cookies=cookies)
            if self._config.get('env') == 'production':
                telegram_handler = AsyncTelegramHandler(
                    config=self._config,
                    level=logging.ERROR
                )
                self.logger.add_handler(telegram_handler)
        self.logger.info('??????????????????')
        session = None
        task_last_opened_events = {}
        while self._config['_running']:
            if not session or self.account_banned or self.site_maintaining:
                sessions = await self.init_session()
                if sessions:
                    session = sessions[0]
                else:
                    await self.logger.error(f'{self.account} {self.name} ?????????????????????5??????')
                    if self._config.get('auto_change_ip'):
                        try:
                            _ = subprocess.check_output(self._config['change_ip_command'].split(' '), stderr=subprocess.STDOUT)
                        except subprocess.CalledProcessError:
                            await self.logger.error(f'{self.account} {self.name} ????????????IP????????????IT???????????????')
                        await self.logger.error(f'{self.account} {self.name} ????????????IP')
                    await asyncio.sleep(300)
            for task in self._tasks:
                self.task_spec = task
                self.task_failed = False
                self.name = task['crawler_name']
                self.logger.extra['name'] = task['crawler_name']
                self.logger.extra['game_type'] = task['game_type']
                self.logger.extra['play_type'] = task['period']
                self.execution_id = str(uuid.uuid4()).replace('-', '')
                if self.task_spec.get('empty') and self.task_spec.get('next_crawl_time', datetime.now() - timedelta(minutes=-1)) > datetime.now():
                    continue
                if self._config['read_from_file']:
                    with open(self._config['read_from_file']) as f:
                        raw_data = json.load(f)
                else:
                    raw_data = await self.crawl_data(session)
                    if self._config['dump']:
                        async with aiofiles.open(f'{self.name}.json', mode='w') as f:
                            await f.write(json.dumps(raw_data, indent=4, ensure_ascii=False))
                last_opened_events = task_last_opened_events.get(self.name, {})
                data = await self.parsing_and_mapping(raw_data, last_opened_events=last_opened_events)
                task_last_opened_events[self.name] = last_opened_events
                if self._config['dump'] and data:
                    async with aiofiles.open(f'{self.name}.log', mode='w') as f:
                        await f.write(text_format.MessageToString(data, as_utf8=True))
                if self._config['dump'] and data:
                    async with aiofiles.open(f'{self.name}.bin', mode='wb') as f:
                        await f.write(data.SerializeToString())
                await self.upload_data(data)
                total_execution_time = (datetime.now() - self.last_execution_time).total_seconds()
                await self.logger.info('????????????', extra={'step': 'total', 'total_process_time': total_execution_time, 'execution_id': self.execution_id})
                if not self.task_failed:
                    self.last_success_time = datetime.now()
                self.last_execution_time = datetime.now()
                await asyncio.sleep(self._config['sleep'])
        if not self._config['read_from_file']:
            await self.logout(session)
        else:
            with open('saved_sessions.pickle', 'wb') as session_file:
                pickle.dump(list(map(lambda s: dict(s._cookie_jar._cookies), sessions)), session_file, pickle.HIGHEST_PROTOCOL)
        await session.close()
        await self.logger.info('????????????')

    async def init_mq(self):
        if self.mq_connection_pool and not self.mq_connection_pool.is_closed:
            await self.mq_connection_pool.close()
        await self.build_mq_connection_pool()
        if self.mq_channel_pool and not self.mq_channel_pool.is_closed:
            await self.mq_channel_pool.close()
        await self.build_channel_pool()

    async def build_mq_connection_pool(self):
        async def connect_mq():
            return await aio_pika.connect_robust(self._config['rabbitmqUrl'])

        self.mq_connection_pool = aio_pika.pool.Pool(connect_mq, max_size=2)

    async def build_channel_pool(self):
        async def create_channel():
            async with self.mq_connection_pool.acquire() as connection:
                return await connection.channel()

        self.mq_channel_pool = aio_pika.pool.Pool(create_channel, max_size=1)

    async def init_session(self, cookies=None):
        sessions = []
        ips = cycle(self._config['ips'])
        for account, account_info in self._config['accounts'].items():
            if not account_info['enabled']:
                continue
            session = None
            if self._config['bind_ip']:
                tcp_connector = aiohttp.TCPConnector(local_addr=(next(ips), 0))
                session = aiohttp.ClientSession(connector=tcp_connector, timeout=aiohttp.ClientTimeout(total=self._config['session_timeout']))
            else:
                session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self._config['session_timeout']))
            if cookies:
                session.cookie_jar.update_cookies(cookies.pop())
            domains = await self.test_site_domains(session)
            if domains:
                self.account = account
                try:
                    if await self.login(session, domains, account, account_info['password']):
                        if await self.redirect_bet_site(session):
                            self._sport_info = await self.query_sport_info(session)
                            if TX.Key.SPORT_EVENT_INFO in self._sport_info:
                                sessions.append(session)
                except Exception as ex:
                    error = traceback.format_exc()
                    await self.logger.error(f'????????????: {str(ex)}', extra={'step': 'login'})
                    await self.logger.warning(error, extra={'step': 'login'})
            if session not in sessions:
                await session.close()
        return sessions

    async def test_site_domains(self, session):
        site_type = Site(self._config['site'])
        site_urls = self._config[f'{site_type.value}_domains']
        success_urls = []
        for site_url in site_urls:
            try:
                async with session.get(site_url) as resp:
                    if resp.status == 200:
                        success_urls.append(site_url)
                    else:
                        await self.logger.warning(f'?????????????????? {site_url}????????????: {resp.status}?????????: {await resp.text()}')
            except aiohttp.client_exceptions.ClientResponseError as ex:
                await self.logger.warning(f'????????????????????????: {ex}')
            except asyncio.TimeoutError:
                await self.logger.warning(f'??????????????????: {site_url}')
        return success_urls

    async def login(self, session, success_domains, account, password):
        form = {
            'txtUser': account.casefold(),
            'txtPassword': self.password_hash(password.casefold()),
            'screenSize': ''
        }
        random.shuffle(success_domains)
        for domain in success_domains:
            home_resp = await session.get(f'{domain}/Index.aspx', headers=self._config['login_headers'])
            if home_resp.status == 200:
                try:
                    async with session.post(
                            f'{domain}/{self._config["api_path"]["login"]}',
                            data=form,
                            headers=self._config['login_headers']) as login_resp:
                        body = await login_resp.text()
                        if login_resp.status == 200:
                            try:
                                data = json.loads(body)
                                if data.get('Lv') == '????????????':
                                    self._session_login_info_map[session] = {
                                        'account': account,
                                        'password': password,
                                        'visited_domain': domain,
                                        'logined_domain': domain,
                                        'success_time': datetime.now()
                                    }
                                    return True
                                elif data.get('StatusCode') == 404:
                                    await self.logger.warning(f'?????? {domain} ???????????????: ??????????????????: {login_resp.status}?????????: {body}')
                                elif '?????????????????????' in data.get('msg', ''):
                                    await self.logger.warning(f'?????? {domain} ???????????????: ??????????????????????????????????????????: {login_resp.status}?????????: {body}')
                                else:
                                    await self.logger.warning(f'?????? {domain} ??????????????????: {login_resp.status}?????????: {body}')
                            except (json.decoder.JSONDecodeError, TypeError, KeyError):
                                await self.logger.warning(f'?????? {domain} ???????????????: {body}')
                        elif login_resp.status == 599:
                            await self.logger.warning(f'?????? {domain} ???????????????: ???IP?????????????????????????????????????????????: {login_resp.status}?????????: {body}')
                        else:
                            await self.logger.warning(f'?????? {domain} ??????????????????: {login_resp.status}?????????: {body}')
                except aiohttp.client_exceptions.ClientResponseError:
                    pass
            else:
                await self.logger.warning(f'?????? {domain} ???????????????: ??????????????????????????????: {home_resp.status}?????????: {await home_resp.text()}')
        await self.logger.warning(f'?????? {success_domains} ?????????')
        return False

    async def relogin(self, session):
        self.relogin_count += 1
        domains = await self.test_site_domains(session)
        login_success = await self.login(session, domains, list(self._config['accounts'].keys())[0], list(self._config['accounts'].values())[0]['password'])
        if not login_success:
            await self.logger.error(f'{self.account} {self.name} ??????????????????', extra={'step': 'crawl_data'})
        elif await self.redirect_bet_site(session):
            self._sport_info = await self.query_sport_info(session)
            if TX.Key.SPORT_EVENT_INFO in self._sport_info:
                await self.logger.info('??????????????????', extra={'step': 'crawl_data'})
        else:
            await self.logger.error(f'{self.account} {self.name} ??????????????????????????????????????????', extra={'step': 'crawl_data'})

    def password_hash(self, password):
        md5_hash = md5(password.encode('utf-8')).hexdigest()
        hmac_md5_hash = hmac.new(md5_hash.encode('utf-8'), password.encode('utf-8'), md5)
        return hmac_md5_hash.hexdigest()

    async def logout(self, session):
        form = {
            '_': round(time() * 1000)
        }
        session_info = self._session_login_info_map[session]
        async with session.post(
                f'{session_info["visited_domain"]}/{self._config["api_path"]["logout"]}',
                data=form,
                headers=self._config['login_headers']) as logout_resp:
            if not logout_resp.ok:
                await self.logger.warning(f'????????????????????????: {logout_resp.status}?????????: {session_info["visited_domain"]}')

    def get_session(self):
        return self._session

    def get_session_info(self):
        return self._session_info

    async def redirect_bet_site(self, session):
        session_info = self._session_login_info_map[session]
        verify_key = None
        available_redirect_sites = []
        session.cookie_jar.update_cookies({
            'icwN2': '0',
            'bdnotice': '0',
            f'Tm_{session_info["account"].upper()}_2': '1',
            f'{session_info["account"].upper()}-2': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        })
        async with session.get(
                f'{session_info["logined_domain"]}/{self._config["api_path"]["redirect_selection"]}',
                headers=self._config['login_headers']) as site_select_resp:
            body = await site_select_resp.text()
            match = re.search(r'verify=([\w\d._-]+)&', body)
            if match:
                verify_key = match.group(1)
            doc =  pq(body)
            urls = doc('#hide_url')[0].value
            available_redirect_sites = urls.split('|')

        if verify_key:
            fast_domain = await self.select_fast_url(session, available_redirect_sites)
            referer = re.search(r'https?:(//[\w\d._-]+)', session_info['logined_domain']).group(1)
            form = {
                'user': session_info['account'],
                'verify': verify_key,
                'ismobile': 'False',
                'homeUrl': referer,
                'isAllowSM': '1'
            }
            async with session.get(f'{fast_domain}/{self._config["api_path"]["redirect_destination"]}?{urlencode(form)}') as redirect_resp:
                if redirect_resp.status == 200 and self._config['api_path']['bet_site_home'] in str(redirect_resp.url):
                    session_info['logined_domain'] = fast_domain
                    return True
        return False

    async def select_fast_url(self, session, accessible_domains):
        loop = asyncio.get_running_loop()
        domain_speed_test = []
        for domain in accessible_domains:
            start_time = loop.time()
            try:
                async with session.get(f'{domain}speed.ashx?sjs={random.random()}') as site_resp:
                    if site_resp.ok:
                        end_time = loop.time()
                        domain_speed_test.append({
                            'domain': domain,
                            'response_time': end_time - start_time
                        })
            except (aiohttp.client_exceptions.ClientResponseError, aiohttp.client_exceptions.ClientConnectorCertificateError) as ex:
                await self.logger.warning(f'????????????????????????: {ex}')
            except Exception as ex:
                await self.logger.warning(f'?????????????????????({domain}): {ex}')
        fastest_domain = None
        if domain_speed_test:
            fastest_domain = min(domain_speed_test, key=lambda d: d['response_time'])['domain']
        else:
            await self.logger.warning(f'??????????????????: {accessible_domains}')
        return re.sub(r'/$', '', fastest_domain)

    async def query_sport_info(self, session):
        # ?????????????????????????????????
        session_info = self._session_login_info_map[session]
        async with session.get(f'{session_info["logined_domain"]}/{self._config["api_path"]["sport_info"]}') as sport_info_resp:
            if not sport_info_resp.ok:
                await self.logger.error(f'{self.account} {self.name} ??????????????????????????????????????????????????????{sport_info_resp.status}')
                await self.logger.warning(f'??????????????????????????????????????????????????????{sport_info_resp.status}?????????: {await sport_info_resp.text()}')
            else:
                raw_text = await sport_info_resp.text()
                try:
                    sport_info = json.loads(raw_text)
                except json.decoder.JSONDecodeError:
                    return {}
                return sport_info
        return {}

    @step_logger('crawl_data')
    async def crawl_data(self, session):
        events = None
        total_page = self.task_spec.get('total_page') or self.task_spec.get('page') or 1
        for page_number in range(1, total_page + 1):
            if self.task_spec.get('page') and self.task_spec.get('page') != page_number:
                continue
            game_type = self.task_spec['game_type']
            sport_type = TX.Value.SportType.get_sport_type(game_type)
            ball_type = TX.Value.BallType.get_ball_type(game_type, self.task_spec['category'])
            is_world_cup = '0'
            if self.task_spec.get('wdls'):
                is_world_cup = '4'
            elif self.task_spec.get('europe_champion'):
                is_world_cup = '3'
            is_olympic = 'true' if sport_type is TX.Value.SportType.SOCCER_OLYMPIC else 'false'
            if is_olympic == 'true':
                sport_type = TX.Value.SportType.SOCCER
            sort_type = TX.Value.SortType.TIME_SORT if sport_type is TX.Value.SportType.SOCCER else TX.Value.SortType.HOT_SORT
            timestamp_millisecond = int(time() * 1000)
            form = {
                'BallType': ball_type.value,
                'BallId': ball_type.get_id().value,
                'Scene': TX.Value.Scene.get_scene(self.task_spec['period']).value,
                'CountryId': TX.Value.CategoryID.get_id(self.task_spec['category']).value,
                'IsOlympic': is_olympic,
                'IsWorldCup': is_world_cup,
                'SortOrder': sort_type.value,
                'PageIndex': page_number,
                'vv': timestamp_millisecond
            }
            api_url = self._config['api_path']['event_api']
            if self.task_spec['category'] in ('pd', 'tg', 'hf'):
                api_url = self._config['api_path']['special_handicap_api']
                del form['Scene']
                del form['CountryId']
            data = None
            if self.next_relogin_time > datetime.now():
                return events
            session_info = self._session_login_info_map[session]
            start_query_time = perf_counter()
            event_list_key = Mapping.event_list_key.get(self.task_spec['category'], TX.Key.EVENT_LIST)
            async with session.get(f'{session_info["logined_domain"]}/{api_url}?{urlencode(form)}') as api_resp:
                end_query_time = perf_counter()
                if api_resp.status == 200:
                    encrypted_data = await api_resp.text()
                    encrypted_parts = encrypted_data.split('???')
                    if len(encrypted_parts) == 4:
                        data = self.decrypt_data(encrypted_parts)
                        end_decryption_time = perf_counter()
                        self.step_log_json['query_time'] = str(end_query_time - start_query_time)
                        self.step_log_json['decryption_time'] = str(end_decryption_time - end_query_time)
                        if not data:
                            await self.logger.error(f'{self.account} {self.name} ????????????????????????: {encrypted_parts[TX.Pos.Encryption.TYPE]}', extra={'step': 'crawl_data'})
                        else:
                            self.account_banned = False
                            self.site_maintaining = False
                            self.relogin_count = 0
                            self.task_spec['total_page'] = self.task_spec.get('page') or data.get(TX.Key.TOTAL_PAGE_NUM, 1) or 1
                            self.step_log_json['total_page'] = data.get(TX.Key.TOTAL_PAGE_NUM)
                            if not events:
                                if not data.get(event_list_key) or (
                                        self.task_spec['period'] == Period.LIVE.value
                                        and self.task_spec.get('page', 20) >
                                        data.get(TX.Key.TOTAL_PAGE_NUM, 0)):
                                    if self.task_spec['period'] == Period.LIVE.value or page_number == 1:
                                        self.task_spec['empty'] = True
                                        self.task_spec['next_crawl_time'] = datetime.now() + timedelta(minutes=1)
                                        await self.logger.warning(f'????????????????????????????????????: {data.get(TX.Key.TOTAL_PAGE_NUM)}', extra={'step': 'crawl_data'})
                                        await self.logger.info('???????????????????????????')
                                    else:
                                        await self.logger.warning('??????????????????: %s' % json.dumps(data), extra={'step': 'crawl_data'})
                                else:
                                    self.task_spec['empty'] = False
                                    events = data
                            else:
                                events[event_list_key].extend(data.get(event_list_key) or [])
                            await asyncio.sleep(self._config['crawl_interval'])
                    else:
                        try:
                            alert_info = json.loads(encrypted_data)
                        except JSONDecodeError:
                            await self.logger.error(f'{self.account} {self.name} ???????????????????????????????????????: {len(encrypted_data)}???????????????: {encrypted_data[-200:]}', extra={'step': 'crawl_data'})
                            await self.relogin(session)
                            return events
                        if alert_info.get(TX.Key.ALERT_TYPE) == TX.Value.LOGOUT_TYPE and alert_info.get(TX.Key.IS_LOGOUT) == 'True':
                            alert_id = alert_info.get(TX.Key.LOGOUT_TYPE_ID)
                            if alert_id in TX.Value.LOGOUT_ALERT_IDS and self.relogin_count < 10:
                                await self.relogin(session)
                            elif alert_id in TX.Value.BANNED_ALERT_IDS:
                                self.account_banned = True
                                if self.next_relogin_time - datetime.now() < timedelta(hours=2):
                                    self.next_relogin_time = datetime.now() + timedelta(hours=2)
                            elif alert_id == TX.Value.SITE_MAINTAIN_ALERT_ID:
                                self.site_maintaining = True
                                if self.next_relogin_time - datetime.now() < timedelta(minutes=30):
                                    self.next_relogin_time = datetime.now() + timedelta(minutes=30)
                            await self.logger.error(
                                f'{self.account} {self.name} ?????????????????????: {Mapping.logout_code.get(alert_info.get(TX.Key.LOGOUT_TYPE_ID), "??????")}?????????: {json.dumps(alert_info, ensure_ascii=False)}',
                                extra={'step': 'crawl_data'})
                        else:
                            await self.logger.error(f'{self.account} {self.name} ???????????????????????????: {json.dumps(alert_info, ensure_ascii=False)}', extra={'step': 'crawl_data'})
                        if not self.account_banned and self.next_relogin_time < datetime.now() and self.relogin_count < 10:
                            await asyncio.sleep(60)
                            await self.relogin(session)
                        elif self.relogin_count >= 10:
                            await self.logger.error(f'{self.account} {self.name} ??????????????????????????????????????????????????????????????????', extra={'step': 'crawl_data'})
                            self.next_relogin_time = datetime.now() + timedelta(hours=3)
                            self.relogin_count = 0
                elif api_resp.status in (599, 429, 403):
                    self.account_banned = True
                    self.next_relogin_time = datetime.now() + timedelta(minutes=1)
                    await self.logger.error(f'{self.account} {self.name} ???????????????????????????????????????', extra={'step': 'crawl_data'})
                    await asyncio.sleep(300)
                else:
                    await self.logger.error(f'{self.account} {self.name} ??????????????????????????????:{api_resp.status}???headers: {api_resp.headers}', extra={'step': 'crawl_data'})
        return events

    def decrypt_data(self, encrypted_parts):
        decrypted_data = None
        # hash key ??????????????????
        hash_key = md5(encrypted_parts[TX.Pos.Encryption.HASH_KEY].replace('\n', '').encode('utf-8')).hexdigest()
        encryption_type = encrypted_parts[TX.Pos.Encryption.TYPE]
        encrypted_info = encrypted_parts[TX.Pos.Encryption.INFO]
        encrypted_data = encrypted_parts[TX.Pos.Encryption.DATA]
        if encryption_type == '2':
            decrypted_info = json.loads(self.xxtea_decrypt(encrypted_info, hash_key))
            decrypted_data = self.decrypt_type2(encrypted_data, decrypted_info, hash_key)
        elif encryption_type == '3':
            decrypted_info = json.loads(self.xxtea_decrypt(encrypted_info, hash_key))
            decrypted_data = self.decrypt_type3(encrypted_data, decrypted_info, hash_key)
        elif encryption_type == '0':
            decrypted_info = json.loads(self.xxtea_decrypt(encrypted_info, hash_key))
            decrypted_data = self.decrypt_type0(encrypted_data, decrypted_info, hash_key)
        elif encryption_type == '4':
            decrypted_data = json.loads(self.xxtea_decrypt(encrypted_data, hash_key))
        return decrypted_data

    def decrypt_type2(self, encrypted_data, info, key):
        decrypted_data = []
        part1_1_len = int(info['part1_1'])
        part1_2_len = int(info['part1_2'])
        part1_3_len = int(info['part1_3'])
        part1_len = int(info['part1'])
        part2_1_len = int(info['part2_1'])
        part2_2_len = int(info['part2_2'])
        part2_3_len = int(info['part2_3'])
        data_parts = []
        start_pos = 0
        # part1
        for part_len in (part1_1_len, part1_2_len, part1_3_len):
            part = encrypted_data[start_pos:start_pos+part_len]
            data_parts.append(part)
            start_pos += part_len
        start_pos = part1_len
        # part2
        for part_len in (part2_1_len, part2_2_len, part2_3_len):
            part = encrypted_data[start_pos:start_pos+part_len]
            data_parts.append(part)
            start_pos += part_len
        # last
        data_parts.append(encrypted_data[start_pos:])
        for idx, part in enumerate(data_parts):
            if idx % 2 == 0:
                decrypted_data.append(self.xxtea_decrypt(part, key))
            else:
                decrypted_data.append(urllib.parse.unquote(part))
        return json.loads(''.join(decrypted_data))

    def decrypt_type3(self, encrypted_data, info, key):
        decrypted_data = []
        part1_1_len = int(info['part1_1'])
        part1_2_len = int(info['part1_2'])
        part1_3_len = int(info['part1_3'])
        part1_len = int(info['part1'])
        part2_1_len = int(info['part2_1'])
        part2_2_len = int(info['part2_2'])
        part2_3_len = int(info['part2_3'])
        part3_1_len = int(info['part3_1'])
        part3_2_len = int(info['part3_2'])
        data_parts = []
        start_pos = 0
        # part1
        for part_len in (part1_1_len, part1_2_len, part1_3_len):
            part = encrypted_data[start_pos:start_pos+part_len]
            data_parts.append(part)
            start_pos += part_len
        start_pos = part1_len
        # part2
        for part_len in (part2_1_len, part2_2_len, part2_3_len):
            part = encrypted_data[start_pos:start_pos+part_len]
            data_parts.append(part)
            start_pos += part_len
        # part3
        for part_len in (part3_1_len, part3_2_len):
            part = encrypted_data[start_pos:start_pos+part_len]
            data_parts.append(part)
            start_pos += part_len
        # last
        data_parts.append(encrypted_data[start_pos:])
        for idx, part in enumerate(data_parts):
            if idx % 2 == 1:
                decrypted_data.append(self.xxtea_decrypt(part, key))
            else:
                decrypted_data.append(urllib.parse.unquote(part))
        return json.loads(''.join(decrypted_data))

    def decrypt_type0(self, encrypted_data, info, key):
        decrypted_data = []
        part1_1_len = int(info['part1_1'])
        part1_2_len = int(info['part1_2'])
        part1_3_len = int(info['part1_3'])
        part1_len = int(info['part1'])
        part2_len = int(info['part2'])
        part3_1_len = int(info['part3_1'])
        part3_2_len = int(info['part3_2'])
        part3_3_len = int(info['part3_3'])
        data_parts = []
        start_pos = 0
        # part1
        for part_len in (part1_1_len, part1_2_len, part1_3_len):
            part = encrypted_data[start_pos:start_pos+part_len]
            data_parts.append(part)
            start_pos += part_len
        start_pos = part1_len
        # part2
        for part_len in (part2_len, ):
            part = encrypted_data[start_pos:start_pos+part_len]
            data_parts.append(part)
            start_pos += part_len
        # part3
        for part_len in (part3_1_len, part3_2_len, part3_3_len):
            part = encrypted_data[start_pos:start_pos+part_len]
            data_parts.append(part)
            start_pos += part_len
        for idx, part in enumerate(data_parts):
            if idx % 2 == 1:
                decrypted_data.append(self.xxtea_decrypt(part, key))
            else:
                decrypted_data.append(urllib.parse.unquote(part))
        return json.loads(''.join(decrypted_data))

    def xxtea_decrypt(self, data, key):
        base64_data = base64.b64decode(data)
        decrypted_data = xxtea.decrypt_utf8(base64_data, key)
        return base64.b64decode(decrypted_data).decode()

    @step_logger('parsing_and_mapping')
    async def parsing_and_mapping(self, raw_data, last_opened_events=None):
        event_list_key = Mapping.event_list_key.get(self.task_spec['category'], TX.Key.EVENT_LIST)
        data = protobuf_spec.ApHdcArr()
        # ???????????????
        if not raw_data or not raw_data.get(event_list_key):
            await self.logger.warning('???????????????', extra={'step': 'parsing_and_mapping'})
            await self.logger.warning('???????????????: %s' % json.dumps(raw_data, ensure_ascii=False), extra={'step': 'parsing_and_mapping'})
            return
        elif raw_data.get(TX.Key.ERROR_MESSAGE):
            await self.logger.warning(f'???????????????????????????: {raw_data[TX.Key.ERROR_MESSAGE]}', extra={'step': 'parsing_and_mapping'})
            return
        elif raw_data.get(TX.Key.EMPTY_EVENT_LIST):
            await self.logger.info('??????????????????', extra={'step': 'parsing_and_mapping'})
            return

        contest_parsing_error_count = 0
        event_proto_list = []
        lst_score = raw_data.get(TX.Key.PERIOD_SCORE)
        period_score_map = self.parse_period_scores(lst_score)
        timestamp_pattern = re.compile(r'/Date\((\d+)\)/')
        for event_json in raw_data[event_list_key]:
            try:
                event = protobuf_spec.ApHdc()
                event.source = Source.TX.value
                sport_name = event_json[TX.Key.EVENT_SPORT_NAME].split('||')[0]
                game_id_key = self.get_game_id_key(self.task_spec['category'], event_json[TX.Key.FULL_1ST_TYPE])
                game_id = event_json[game_id_key] or event_json[TX.Key.EVENT_ID_GP] or '4444444444'
                event.game_id = self.modify_game_id(game_id, sport_name)
                event.ip = 'python'
                event.status = '0'
                timestamp_str = timestamp_pattern.search(event_json[TX.Key.EVENT_TIME]).group(1)
                event_time = datetime.fromtimestamp(int(timestamp_str) // 1000)
                event.event_time = event_time.strftime('%Y-%m-%d %H:%M:%S')
                event.source_updatetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                event.live = 'true' if event_json[TX.Key.LIVE_TYPE] == '2' else 'false'
                event_play_time = str(int(event_json[TX.Key.EVENT_LIVE_TIME]))
                period_score = period_score_map.get(event_json.get(TX.Key.EVENT_SPORT_CODE), {}).get(event_json[TX.Key.EVENT_ID_GP])
                event.live_time = self.get_live_time(event_json[TX.Key.EVENT_LIVE_PERIOD], event_play_time, period_score)
                event_info = protobuf_spec.information()
                league_names = event_json[TX.Key.EVENT_LEAGUE_NAME_WITH_POSTFIX].split('||')
                postfixed_league_names = self.add_league_postfix(league_names, sport_name, event_json, Period.FULL)
                event_info.league = postfixed_league_names[TX.Pos.Lang.TRADITIONAL_CHINESE]
                # ?????????????????????????????????
                if self.task_spec['period'] == Period.LIVE.value and self.task_spec[
                        'game_type'] == GameType.soccer.value and EXCLUDED_LEAGUES.search(
                            event_info.league):
                    continue
                event_info.cn_league = postfixed_league_names[TX.Pos.Lang.SIMPLIFIED_CHINESE]
                event_info.en_league = postfixed_league_names[TX.Pos.Lang.ENGLISH]
                if '??????' in event_info.league:
                    event.score.CopyFrom(
                        protobuf_spec.score(
                            home=event_json[TX.Key.EVENT_SCORE_HOME] or '0',
                            away=event_json[TX.Key.EVENT_SCORE_AWAY] or '0'
                        )
                    )
                    event.conner.CopyFrom(
                        protobuf_spec.conner(
                            home=event.score.home or '0',
                            away=event.score.away or '0'
                        )
                    )
                else:
                    home_score, away_score = self.get_period_score(period_score, event_info.league)
                    event.score.CopyFrom(
                        protobuf_spec.score(
                            home=home_score or event_json[TX.Key.EVENT_SCORE_HOME] or '0',
                            away=away_score or event_json[TX.Key.EVENT_SCORE_AWAY] or '0'
                        )
                    )
                event.redcard.CopyFrom(
                    protobuf_spec.redcard(
                        home=str(event_json[TX.Key.EVENT_RED_CARD_HOME]) or '0',
                        away=str(event_json[TX.Key.EVENT_RED_CARD_AWAY]) or '0'
                    )
                )
                event.yellowcard.CopyFrom(protobuf_spec.yellowcard(home='0', away='0'))
                home_team, away_team = self.get_correct_teams(
                    event_info.league,
                    event_json[TX.Key.TEAM_A],
                    event_json[TX.Key.TEAM_B],
                    event_json[TX.Key.TEAM_ORDER]
                )
                home_team_info = protobuf_spec.infoHA(
                    team_name=home_team[TX.Pos.Lang.TRADITIONAL_CHINESE],
                    pitcher='',
                    cn_name=home_team[TX.Pos.Lang.SIMPLIFIED_CHINESE],
                    en_name=home_team[TX.Pos.Lang.ENGLISH]
                )
                event_info.home.CopyFrom(home_team_info)
                away_team_info = protobuf_spec.infoHA(
                    team_name=away_team[TX.Pos.Lang.TRADITIONAL_CHINESE],
                    pitcher='',
                    cn_name=away_team[TX.Pos.Lang.SIMPLIFIED_CHINESE],
                    en_name=away_team[TX.Pos.Lang.ENGLISH]
                )
                event_info.away.CopyFrom(away_team_info)
                event.information.CopyFrom(event_info)
                game_type = GameType[self.task_spec['game_type']]
                event.game_class = TXCrawler.game_class_convert(game_type, postfixed_league_names[TX.Pos.Lang.TRADITIONAL_CHINESE])
                if self.task_spec['period'] in (Period.FULL.value,
                                                Period.LIVE.value, '2nd',
                                                'team total', 'special', 'set',
                                                'single_set', 'tennis_set',
                                                'set_1_3', 'set_1_7',
                                                'pingpong_volleyball_set',
                                                'first_blood', 'kill_hero'):
                    # ??????
                    spread = self.extract_spread(event_json, Period.FULL)
                    total = self.extract_total(event_json, Period.FULL)
                    money_line, draw = self.extract_money_line(event_json, Period.FULL)
                    esre = self.extract_esre(event_json, Period.FULL)
                    parity = self.extract_parity(event_json, Period.FULL)
                    if event_json[TX.Key.TEAM_ORDER] != '0':
                        self.reverse_odds(spread, money_line, esre)
                    event_full = protobuf_spec.ApHdc()
                    event_full.CopyFrom(event)
                    postfixed_league_names = self.add_league_postfix(league_names, sport_name, event_json, Period.FULL)
                    event_full.information.league = postfixed_league_names[TX.Pos.Lang.TRADITIONAL_CHINESE]
                    event_full.information.cn_league = postfixed_league_names[TX.Pos.Lang.SIMPLIFIED_CHINESE]
                    event_full.information.en_league = postfixed_league_names[TX.Pos.Lang.ENGLISH]
                    second_half_pattern = re.compile(r'(?????????|??????|?????????)')
                    if self.task_spec['period'] == Period.LIVE.value:
                        event_full.game_type = Period.LIVE_FULL.value
                    elif self.task_spec['period'] == 'set':
                        if event_json[TX.Key.FULL_1ST_TYPE] == '11':
                            event_full.game_type = '1q'
                            event_full.information.league += '-?????????'
                            event_full.information.cn_league += '-?????????'
                            event_full.information.en_league += ' - 1Q'
                            if event.game_class == GameType.otherbasketball.value:
                                continue
                        elif event_json[TX.Key.FULL_1ST_TYPE] == '12':
                            event_full.game_type = '2q'
                            event_full.information.league += '-?????????'
                            event_full.information.cn_league += '-?????????'
                            event_full.information.en_league += ' - 2Q'
                        elif event_json[TX.Key.FULL_1ST_TYPE] == '13':
                            event_full.game_type = '3q'
                            event_full.information.league += '-?????????'
                            event_full.information.cn_league += '-?????????'
                            event_full.information.en_league += ' - 3Q'
                        elif event_json[TX.Key.FULL_1ST_TYPE] == '14':
                            event_full.game_type = '4q'
                            event_full.information.league += '-?????????'
                            event_full.information.cn_league += '-?????????'
                            event_full.information.en_league += ' - 4Q'
                        else:
                            event_full.game_type = Period.FULL.value
                    elif self.task_spec['period'] == '2nd':
                        event_full.game_type = Period.SECOND_HALF.value
                    elif second_half_pattern.search(event_full.information.league) and event.game_class == GameType.basketball.value:
                        event_full.game_type = Period.SECOND_HALF.value
                    elif game_type is GameType.baseball and self.task_spec['period'] in ('set_1_3', 'set_1_7'):
                        event_full.game_type = Period.FIRST_HALF.value
                    else:
                        event_full.game_type = Period.FULL.value
                    event_full.twZF.CopyFrom(spread)
                    event_full.twDS.CopyFrom(total)
                    event_full.de.CopyFrom(money_line)
                    event_full.draw = str(draw)
                    event_full.esre.CopyFrom(esre)
                    event_full.sd.CopyFrom(parity)
                    event_proto_list.append(event_full)
                    # ??????
                    if event_json[TX.Key.SECOND_HALF]:
                        spread_1st = self.extract_spread(event_json, Period.FIRST_HALF)
                        total_1st = self.extract_total(event_json, Period.FIRST_HALF)
                        money_line_1st, draw = self.extract_money_line(event_json, Period.FIRST_HALF)
                        esre_1st = self.extract_esre(event_json, Period.FIRST_HALF)
                        parity_1st = self.extract_parity(event_json, Period.FIRST_HALF)
                        if event_json[TX.Key.TEAM_ORDER] != '0':
                            self.reverse_odds(spread_1st, money_line_1st, esre_1st)
                        event_1st = protobuf_spec.ApHdc()
                        event_1st.CopyFrom(event)
                        postfixed_league_names = self.add_league_postfix(league_names, sport_name, event_json, Period.FIRST_HALF)
                        event_1st.information.league = postfixed_league_names[TX.Pos.Lang.TRADITIONAL_CHINESE]
                        event_1st.information.cn_league = postfixed_league_names[TX.Pos.Lang.SIMPLIFIED_CHINESE]
                        event_1st.information.en_league = postfixed_league_names[TX.Pos.Lang.ENGLISH]
                        if self.task_spec['period'] == Period.LIVE.value:
                            event_1st.game_type = Period.LIVE_FIRST_HALF.value
                        elif self.task_spec['period'] == 'set':
                            if event_json[TX.Key.FULL_1ST_TYPE] == '11':
                                event_1st.game_type = '1q'
                                event_1st.information.league += '-?????????'
                                event_1st.information.cn_league += '-?????????'
                                event_1st.information.en_league += ' - 1Q'
                            elif event_json[TX.Key.FULL_1ST_TYPE] == '12':
                                event_1st.game_type = '2q'
                                event_1st.information.league += '-?????????'
                                event_1st.information.cn_league += '-?????????'
                                event_1st.information.en_league += ' - 2Q'
                            elif event_json[TX.Key.FULL_1ST_TYPE] == '13':
                                event_1st.game_type = '3q'
                                event_1st.information.league += '-?????????'
                                event_1st.information.cn_league += '-?????????'
                                event_1st.information.en_league += ' - 3Q'
                            elif event_json[TX.Key.FULL_1ST_TYPE] == '14':
                                event_1st.game_type = '4q'
                                event_1st.information.league += '-?????????'
                                event_1st.information.cn_league += '-?????????'
                                event_1st.information.en_league += ' - 4Q'
                            else:
                                event_1st.game_type = Period.FIRST_HALF.value
                        elif self.task_spec['period'] == '2nd':
                            event_1st.game_type = Period.SECOND_HALF.value
                        elif game_type in (GameType.tennis, GameType.eSport, GameType.pingpong):
                            event_1st.game_type = Period.FULL.value
                            event_1st.game_id += '1'
                        else:
                            event_1st.game_type = Period.FIRST_HALF.value
                        event_1st.twZF.CopyFrom(spread_1st)
                        event_1st.twDS.CopyFrom(total_1st)
                        event_1st.de.CopyFrom(money_line_1st)
                        event_1st.draw = str(draw)
                        event_1st.esre.CopyFrom(esre_1st)
                        event_1st.sd.CopyFrom(parity_1st)
                        event_proto_list.append(event_1st)
                # ???????????????????????????
                elif self.task_spec['period'] == ('first_last_point'):
                    event_first_last = protobuf_spec.ApHdc()
                    event_first_last.CopyFrom(event)
                    if self.task_spec['game_type'] == 'hockey':
                        event_first_last.game_type = Period.FULL.value
                        first = self.extract_spread(event_json, Period.FULL)
                        # ????????????????????????????????????
                        first.homeZF.line, first.awayZF.line = first.awayZF.line, first.homeZF.line
                        first.homeZF.odds, first.awayZF.odds = first.awayZF.odds, first.homeZF.odds
                        last = self.extract_total(event_json, Period.FULL)
                        highest, _ = self.extract_money_line(event_json, Period.FULL)
                    else:
                        event_first_last.game_type = Period.MULTI.value
                        first, last, highest = self.extract_basketball_special_handicap(event_json)
                    event_first_last.twZF.CopyFrom(first)
                    event_first_last.twDS.CopyFrom(last)
                    event_first_last.de.CopyFrom(highest)
                    event_proto_list.append(event_first_last)
                # ??????
                elif self.task_spec['category'] == 'pd':
                    event_pd = protobuf_spec.ApHdc()
                    event_pd.CopyFrom(event)
                    # ??????
                    if event_json[TX.Key.FULL_1ST_TYPE] == '0':
                        if event_json[TX.Key.LIVE_TYPE] == '2':
                            event_pd.game_type = Period.CORRECT_SCORE_LIVE.value
                        else:
                            event_pd.game_type = Period.CORRECT_SCORE.value
                        event_pd.multi = self.extract_correct_score(event_json)
                    # ??????
                    else:
                        if event_json[TX.Key.LIVE_TYPE] == '1':
                            event_pd.game_type = Period.CORRECT_SCORE_LIVE_1ST_HALF.value
                        else:
                            event_pd.game_type = Period.CORRECT_SCORE_1ST_HALF.value
                        event_pd.multi = self.extract_correct_score(event_json)
                    event_proto_list.append(event_pd)
                # ?????????
                elif self.task_spec['category'] == 'tg':
                    event_tg_full = protobuf_spec.ApHdc()
                    event_tg_first_half = protobuf_spec.ApHdc()
                    event_tg_full.CopyFrom(event)
                    event_tg_first_half.CopyFrom(event)
                    event_tg_first_half.game_id += '1'
                    tg_full, tg_first_half= self.extract_score_sum(event_json)
                    if event_json[TX.Key.LIVE_TYPE] == '2':
                        event_tg_full.game_type = Period.SCORE_SUM_LIVE.value
                        event_tg_first_half.game_type = Period.SCORE_SUM_LIVE_1ST_HALF.value
                    else:
                        event_tg_full.game_type = Period.SCORE_SUM.value
                        event_tg_first_half.game_type = Period.SCORE_SUM_1ST_HALF.value
                    event_tg_full.multi = json.dumps(tg_full)
                    event_tg_first_half.multi = json.dumps(tg_first_half)
                    event_proto_list.append(event_tg_full)
                    event_proto_list.append(event_tg_first_half)
                # ?????????
                elif self.task_spec['category'] == 'hf':
                    event_hf = protobuf_spec.ApHdc()
                    event_hf.CopyFrom(event)
                    if event_json[TX.Key.LIVE_TYPE] == '2':
                        event_hf.game_type = Period.HALF_FULL_SCORE_LIVE.value
                    else:
                        event_hf.game_type = Period.HALF_FULL_SCORE.value
                    event_hf.multi = self.extract_half_full_score(event_json)
                    event_proto_list.append(event_hf)

            except (IndexError, KeyError, TypeError):
                contest_parsing_error_count += 1
                await self.logger.warning('????????????????????????: %s' % traceback.format_exc(), extra={'step': 'parsing_and_mapping'})
                await self.logger.warning('??????????????????: %s' % json.dumps(event_json, ensure_ascii=False), extra={'step': 'parsing_and_mapping'})
                if contest_parsing_error_count > 10:
                    self.task_failed = True
                    await self.logger.error(f'{self.account} {self.name} ????????????????????????10????????????????????????????????????', extra={'step': 'parsing_and_mapping', 'execution_id': self.execution_id})
        data.aphdc.extend(event_proto_list)
        current_opened_events = {}
        for event in event_proto_list:
            current_opened_events[event.game_id] = event
        if last_opened_events and self.task_spec.get('page'):
            disappear_event_ids = set(last_opened_events.keys()) - set(current_opened_events.keys())
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            for game_id in disappear_event_ids:
                event = last_opened_events[game_id]
                event.source_updatetime = current_time
                event.usZF.CopyFrom(self._zero_uszf)
                event.usDS.CopyFrom(self._zero_usds)
                event.twZF.CopyFrom(self._zero_twzf)
                event.twDS.CopyFrom(self._zero_twds)
                event.de.CopyFrom(self._zero_de)
                event.sd.CopyFrom(self._zero_sd)
                event.esre.CopyFrom(self._zero_esre)
                event.draw = '0'
                event.multi = ''
                data.aphdc.append(event)
                await self.logger.warning(
                    '??????(%s,[%s] %s %s %s)????????????????????????' %
                    (game_id, event.event_time, event.information.league,
                     event.information.home.team_name,
                     event.information.away.team_name),
                    extra={'step': 'parsing_and_mapping'})
            last_opened_events.clear()
        last_opened_events.update(current_opened_events)

        return data

    def get_game_id_key(self, category, period):
        key = TX.Key.EVENT_ID
        if category in ('all', 'soccer') and period == '0':
            key = TX.Key.EVENT_ID
        elif category in ('all', 'soccer') and period == '1':
            key = TX.Key.EVENT_ID_GP
        elif category in ('pd', 'tg', 'hf') and period == '0':
            key = TX.Key.EVENT_ID_1
        elif category in ('pd', 'tg', 'hf') and period == '1':
            key = TX.Key.EVENT_ID_GP
        return key

    def modify_game_id(self, game_id, sport_name):
        prefix = Mapping.game_id_prefix.get(sport_name, '')
        return f'{prefix}{game_id}'

    def parse_period_scores(self, lst_score):
        period_map = {}
        if not lst_score:
            return {}
        num_pattern = re.compile(r'(\d+)')
        for scores_by_sport in lst_score:
            sport_type = scores_by_sport.get(TX.Key.PERIOD_SCORE_BALL_TYPE)
            sport_period_map = {}
            scores = scores_by_sport.get(TX.Key.PERIOD_SCORE_LIST, [])
            if not scores:
                continue
            for score in scores:
                try:
                    event_period_id = num_pattern.search(score.get(TX.Key.EVENT_PERIOD_ID)).group(1)
                    reverse = score.get(TX.Key.EVENT_PERIOD_ID, '').startswith('lq')
                    period_type = Mapping.period_id.get(score.get(TX.Key.EVENT_PERIOD), TX.Value.PeriodId.NOT_START)
                    if not reverse:
                        sport_period_map[event_period_id] = {
                            'period': Mapping.period_name[period_type],
                            'period_code': score.get(TX.Key.EVENT_PERIOD),
                            'time': score.get(TX.Key.PERIOD_TIME),
                            'home_sum': score.get(TX.Key.HOME_PERIOD_SCORE_SUM),
                            'home_scores': score.get(TX.Key.HOME_PERIOD_SCORES, '').split(','),
                            'away_sum': score.get(TX.Key.AWAY_PERIOD_SCORE_SUM),
                            'away_scores': score.get(TX.Key.AWAY_PERIOD_SCORES, '').split(',')
                        }
                    else:
                        sport_period_map[event_period_id] = {
                            'period': Mapping.period_name[period_type],
                            'period_code': score.get(TX.Key.EVENT_PERIOD),
                            'time': score.get(TX.Key.PERIOD_TIME),
                            'home_sum': score.get(TX.Key.AWAY_PERIOD_SCORE_SUM),
                            'home_scores': score.get(TX.Key.AWAY_PERIOD_SCORES, '').split(','),
                            'away_sum': score.get(TX.Key.HOME_PERIOD_SCORE_SUM),
                            'away_scores': score.get(TX.Key.HOME_PERIOD_SCORES, '').split(',')
                        }
                except AttributeError:
                    pass
            period_map[sport_type] = sport_period_map
        return period_map

    def get_live_time(self, live_period, time_str, period_score):
        if live_period:
            live_period = int(live_period)
        if live_period == TX.Value.LivePeriod.NOT_START.value:
            return Mapping.live_time_prefix[TX.Value.LivePeriod.NOT_START]
        elif live_period == TX.Value.LivePeriod.FIRST_HALF.value:
            return f'{Mapping.live_time_prefix[TX.Value.LivePeriod.FIRST_HALF]} {time_str}'
        elif live_period == TX.Value.LivePeriod.SECOND_HALF.value:
            return f'{Mapping.live_time_prefix[TX.Value.LivePeriod.SECOND_HALF]} {time_str}'
        elif live_period == TX.Value.LivePeriod.INTERMISSION.value:
            return Mapping.live_time_prefix[TX.Value.LivePeriod.INTERMISSION]
        elif period_score:
            period = period_score.get('period', 0)
            if period_score.get('time') != '????????????':
                return f'{period} {period_score["time"]}'
        return '0'

    def get_period_score(self, score_map, league_name):
        home_score = ''
        away_score = ''
        if score_map:
            try:
                period_code = score_map.get('period_code', 0)
                if period_code == '21' and '?????????' in league_name:
                    home_score = score_map['home_scores'][0]
                    away_score = score_map['away_scores'][0]
                elif period_code == '22' and '?????????' in league_name:
                    home_score = score_map['home_scores'][1]
                    away_score = score_map['away_scores'][1]
                elif period_code == '23' and '?????????' in league_name:
                    home_score = score_map['home_scores'][2]
                    away_score = score_map['away_scores'][2]
                elif period_code == '24' and '?????????' in league_name:
                    home_score = score_map['home_scores'][3]
                    away_score = score_map['away_scores'][3]
                else:
                    home_score = score_map['home_sum']
                    away_score = score_map['away_sum']
            except (KeyError, IndexError):
                pass
        return home_score, away_score

    def add_league_postfix(self, league_names, sport_name, event_json, period):
        names = []
        if sport_name in ('??????', '????????????', '?????????'):
            if league_names[0] == event_json.get("s_FilterAllianceName") and sport_name != '????????????':
                if period is Period.FULL:
                    names.append(f'{league_names[0]}-???????????????')
                    names.append(f'{league_names[1]}-???????????????')
                    names.append(f'{league_names[2]}-Game Handicap')
                elif sport_name != '?????????':
                    names.append(f'{league_names[0]}-???????????????')
                    names.append(f'{league_names[1]}-???????????????')
                    names.append(f'{league_names[2]}-Set Handicap')
                else:
                    names.append(f'{league_names[0]}-???????????????')
                    names.append(f'{league_names[1]}-???????????????')
                    names.append(f'{league_names[2]}-Point Handicap')
            else:
                names.append(event_json.get("s_FilterAllianceName", ''))
                postfix = event_json.get('s_FilterAllianceName').split('-')[-1]
                postfix_mapping = Mapping.league_postfix.get(postfix.strip())
                if postfix_mapping:
                    names.append(f'{league_names[1]}{postfix_mapping["cn"]}')
                    names.append(f'{league_names[2]}{postfix_mapping["en"]}')
                else:
                    names.append(league_names[1])
                    names.append(league_names[2])
            return names
        return league_names

    def get_correct_teams(self, league_name, team_a, team_b, team_order):
        # ????????????????????????????????????????????????
        # ??????????????????
        reverse_team = (team_order == '0')
        team_a_names = team_a.split('||')
        team_b_names = team_b.split('||')
        if 'NBA 2K' in league_name or '????????????' in league_name:
            reverse_team = True
        if not reverse_team or self.task_spec['game_type'] not in (GameType.baseball.value, GameType.basketball.value, GameType.tennis.value):
            return team_a_names, team_b_names
        return team_b_names, team_a_names

    @staticmethod
    def game_class_convert(game_type, league):
        """Specify game class based on game type and league name"""
        game_class = None
        if game_type is GameType.baseball:
            if ('????????????' in league or 'MLB' in league) and '3A' not in league:
                game_class = GameType.mlb
            elif '??????????????????' in league or 'NPB' in league:
                game_class = GameType.npb
            elif 'CPBL' in league:
                game_class = GameType.cpbl
            else:
                game_class = GameType.kbo
        elif game_type == GameType.basketball:
            if ('??????????????????' in league or 'NBA' in league) and ('WNBA' not in league and 'Summer League' not in league and '????????????' not in league):
                game_class = GameType.basketball
            else:
                game_class = GameType.otherbasketball
        elif game_type is GameType.hockey:
            game_class = GameType.hockey
        elif game_type is GameType.football:
            game_class = GameType.football
        elif game_type is GameType.tennis:
            game_class = GameType.tennis
        elif game_type is GameType.eSport:
            game_class = GameType.eSport
        elif re.search(r'(????????????|?????????????????????|?????????|???????????????\(?????????\)|???????????????|??????????????????|??????????????????)', league) and '?????????' not in league:
            game_class = GameType.UCL
        elif game_type is GameType.soccer:
            game_class = GameType.soccer
        else:
            game_class = GameType.other
        return game_class.value

    def extract_spread(self, event_json, period):
        spread_line = '-0'
        advanced_team = 1
        home_odds = '0'
        away_odds = '0'
        if period is Period.FULL and event_json[TX.Key.SPREAD_FULL_CLOSE]:
            spread_line = event_json[TX.Key.SPREAD_LINE]
            advanced_team = event_json[TX.Key.SPREAD_ADVANCED_TEAM]
            if spread_line:
                if self.task_spec['game_type'] == GameType.soccer.value:
                    line_num = self._soccer_line_convert(spread_line)
                    spread_line = self._compute_soccer_line(line_num)
                    spread_line = self._compute_other_line(spread_line, '')
                else:
                    sign = '-' if int(event_json[TX.Key.SPREAD_OTHER_ADVANCED_TEAM]) > 1 else '+'
                    line_value = f'{sign}{event_json[TX.Key.SPREAD_LINE_OTHER_VALUE]}'
                    spread_line = self._compute_other_line(spread_line, line_value)
                home_odds = self.get_odds(event_json[TX.Key.SPREAD_HOME])
                away_odds = self.get_odds(event_json[TX.Key.SPREAD_AWAY])
        elif period is Period.FIRST_HALF and event_json[TX.Key.SPREAD_1ST_CLOSE]:
            spread_line = event_json[TX.Key.SPREAD_1ST_LINE]
            advanced_team = event_json[TX.Key.SPREAD_1ST_ADVANCED_TEAM]
            if spread_line:
                if self.task_spec['game_type'] == GameType.soccer.value:
                    line_num = self._soccer_line_convert(spread_line)
                    spread_line = self._compute_soccer_line(line_num)
                    spread_line = self._compute_other_line(spread_line, '')
                else:
                    sign = '-' if int(event_json[TX.Key.SPREAD_1ST_OTHER_ADVANCED_TEAM]) > 1 else '+'
                    line_value = f'{sign}{event_json[TX.Key.SPREAD_1ST_LINE_OTHER_VALUE]}'
                    spread_line = self._compute_other_line(spread_line, line_value)
                home_odds = self.get_odds(event_json[TX.Key.SPREAD_1ST_HOME])
                away_odds = self.get_odds(event_json[TX.Key.SPREAD_1ST_AWAY])
        if not spread_line:
            spread_line = '-0'
        home_line, away_line = self._line_add_sign(spread_line, advanced_team)
        return protobuf_spec.twZF(
            homeZF=protobuf_spec.typeZF(
                line=home_line,
                odds=str(home_odds)
            ),
            awayZF=protobuf_spec.typeZF(
                line=away_line,
                odds=str(away_odds)
            )
        )

    def _soccer_line_convert(self, line):
        parts = line.split('.')
        converted_line = int(parts[0]) * 4
        if len(parts) == 2:
            num = parts[1]
            if num == '1':
                converted_line += 1
            elif num == '5':
                converted_line += 2
            elif num == '6':
                converted_line += 3
        return converted_line

    def _compute_soccer_line(self, line_num):
        spread_line_num = line_num * 0.25
        if line_num % 2 == 0:
            if line_num >= 0 and line_num % 4 == 0:
                return f'{int(spread_line_num)}+0'
            return str(spread_line_num)
        return f'{spread_line_num-0.25}/{spread_line_num+0.25}'

    def _compute_other_line(self, line, value):
        if line and line[-2:] == '.5' and '/' not in line:
            return f'{line[:-2]}-100'
        return f'{line}{value}'

    def _line_add_sign(self, line, advanced_team):
        if line == '-0':
            return line, '+0'
        if advanced_team == TX.Value.AdvancedTeam.HOME.value:
            return f'-{line}', f'+{line}'
        if '-' in line[0]:
            return line, f'+{line[1:]}'
        return f'+{line}', f'-{line}'

    def extract_total(self, event_json, period):
        total_line = '0'
        over = '0'
        under = '0'
        if period is Period.FULL and event_json[TX.Key.TOTAL_FULL_CLOSE]:
            total_line = event_json[TX.Key.TOTAL_LINE] or ''
            if total_line:
                if self.task_spec['game_type'] == GameType.soccer.value:
                    line_num = self._soccer_line_convert(total_line)
                    total_line = self._compute_soccer_line(line_num)
                    total_line = self._compute_other_line(total_line, '')
                else:
                    sign_value = event_json[TX.Key.TOTAL_LINE_SIGN]
                    if sign_value and int(sign_value) not in (0, 3):
                        sign = '-' if int(sign_value) > 1 else '+'
                        line_value = f'{sign}{event_json[TX.Key.TOTAL_LINE_OTHER_VALUE]}'
                        total_line = self._compute_other_line(total_line, line_value)
                over = self.get_odds(event_json[TX.Key.TOTAL_OVER])
                under = self.get_odds(event_json[TX.Key.TOTAL_UNDER])
        elif period is Period.FIRST_HALF and event_json[TX.Key.TOTAL_1ST_CLOSE]:
            total_line = event_json[TX.Key.TOTAL_1ST_LINE] or ''
            if total_line:
                if self.task_spec['game_type'] == GameType.soccer.value:
                    line_num = self._soccer_line_convert(total_line)
                    total_line = self._compute_soccer_line(line_num)
                    total_line = self._compute_other_line(total_line, '')
                else:
                    sign_value = event_json[TX.Key.TOTAL_1ST_LINE_SIGN]
                    if sign_value and int(sign_value) not in (0, 3):
                        sign = '-' if int(sign_value) > 1 else '+'
                        line_value = f'{sign}{event_json[TX.Key.TOTAL_1ST_LINE_OTHER_VALUE]}'
                        total_line = self._compute_other_line(total_line, line_value)
                over = self.get_odds(event_json[TX.Key.TOTAL_1ST_OVER])
                under = self.get_odds(event_json[TX.Key.TOTAL_1ST_UNDER])
        if total_line and total_line[-2:] == '.5' and '/' not in total_line:
            total_line = f'{total_line[:-2]}-100'
        elif not total_line:
            total_line = '-0+0'
        elif '+' not in total_line[1:] and '-' not in total_line[1:] and '/' not in total_line:
            total_line += '+0'
        return protobuf_spec.typeDS(
            line=total_line,
            over=str(over),
            under=str(under)
        )

    def extract_money_line(self, event_json, period):
        if period is Period.FULL and event_json[TX.Key.MONEY_LINE_FULL_CLOSE]:
            return protobuf_spec.onetwo(
                home=str(self.get_odds(event_json.get(TX.Key.MONEY_LINE_HOME, 0))),
                away=str(self.get_odds(event_json.get(TX.Key.MONEY_LINE_AWAY, 0)))
            ), event_json.get(TX.Key.MONEY_LINE_DRAW, '0')
        elif period is Period.FIRST_HALF and event_json[TX.Key.MONEY_LINE_1ST_CLOSE]:
            return protobuf_spec.onetwo(
                home=str(self.get_odds(event_json.get(TX.Key.MONEY_LINE_1ST_HOME, 0))),
                away=str(self.get_odds(event_json.get(TX.Key.MONEY_LINE_1ST_AWAY, 0)))
            ), event_json.get(TX.Key.MONEY_LINE_1ST_DRAW, '0')
        return protobuf_spec.onetwo(), ''

    def extract_esre(self, event_json, period):
        advanced_team = protobuf_spec.whichTeam.home
        if period is Period.FULL and event_json[TX.Key.ESRE_FULL_CLOSE]:
            if event_json.get(TX.Key.SPREAD_ADVANCED_TEAM) == TX.Value.AdvancedTeam.AWAY.value:
                advanced_team = protobuf_spec.whichTeam.away
            return protobuf_spec.Esre(
                let=advanced_team,
                home=str(self.get_odds(event_json.get(TX.Key.ESRE_HOME, '0'))),
                away=str(self.get_odds(event_json.get(TX.Key.ESRE_AWAY, '0')))
            )
        elif period is Period.FIRST_HALF and event_json[TX.Key.ESRE_1ST_CLOSE]:
            if event_json.get(TX.Key.SPREAD_1ST_ADVANCED_TEAM) == TX.Value.AdvancedTeam.AWAY.value:
                advanced_team = protobuf_spec.whichTeam.away
            return protobuf_spec.Esre(
                let=advanced_team,
                home=str(self.get_odds(event_json.get(TX.Key.ESRE_1ST_HOME, '0'))),
                away=str(self.get_odds(event_json.get(TX.Key.ESRE_1ST_AWAY, '0')))
            )
        return protobuf_spec.Esre(let=advanced_team, home='0', away='0')

    def extract_parity(self, event_json, period):
        if period is Period.FULL and event_json[TX.Key.PARITY_FULL_CLOSE]:
            odd = str(self.get_odds(event_json.get(TX.Key.PARITY_ODD, 0)))
            even = str(self.get_odds(event_json.get(TX.Key.PARITY_EVEN, 0)))
            if odd[0] != '-' and even[0] != '-':
                return protobuf_spec.onetwo(
                    home=odd,
                    away=even
                )
        elif period is Period.FIRST_HALF and event_json[TX.Key.PARITY_1ST_CLOSE]:
            odd = str(self.get_odds(event_json.get(TX.Key.PARITY_1ST_ODD, 0)))
            even = str(self.get_odds(event_json.get(TX.Key.PARITY_1ST_EVEN, 0)))
            if odd[0] != '-' and even[0] != '-':
                return protobuf_spec.onetwo(
                    home=odd,
                    away=even
                )
        return protobuf_spec.onetwo(home='0', away='0')

    def extract_basketball_special_handicap(self, event_json):
        # ??????
        first_goal = protobuf_spec.twZF(
            homeZF=protobuf_spec.typeZF(
                line='',
                odds=str(self.get_odds(event_json[TX.Key.FIRST_GOAL_HOME])),
            ),
            awayZF=protobuf_spec.typeZF(
                line='',
                odds=str(self.get_odds(event_json[TX.Key.FIRST_GOAL_AWAY]))
            )
        )
        # ??????
        last_goal = protobuf_spec.typeDS(
            line='',
            over=str(self.get_odds(event_json[TX.Key.LAST_GOAL_HOME])),
            under=str(self.get_odds(event_json[TX.Key.LAST_GOAL_AWAY]))
        )
        # ???????????????
        single_set_highest = protobuf_spec.onetwo(
            home=str(self.get_odds(event_json[TX.Key.SINGLE_SET_HIGHEST_SCORE_HOME])),
            away=str(self.get_odds(event_json[TX.Key.SINGLE_SET_HIGHEST_SCORE_AWAY]))
        )
        return first_goal, last_goal, single_set_highest

    def extract_correct_score(self, event_json):
        correct_score = {f'{home}-{away}': '0' for home, away in product([0, 1, 2, 3, 4], repeat=2)}
        if event_json.get(TX.Key.CORRECT_SCORE_1_0) is not None:
            correct_score['1-0'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_1_0]))
            correct_score['2-0'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_2_0]))
            correct_score['2-1'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_2_1]))
            correct_score['3-0'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_3_0]))
            correct_score['3-1'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_3_1]))
            correct_score['3-2'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_3_2]))
            correct_score['4-0'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_4_0]))
            correct_score['4-1'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_4_1]))
            correct_score['4-2'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_4_2]))
            correct_score['4-3'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_4_3]))
            correct_score['0-1'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_0_1]))
            correct_score['0-2'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_0_2]))
            correct_score['1-2'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_1_2]))
            correct_score['0-3'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_0_3]))
            correct_score['1-3'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_1_3]))
            correct_score['2-3'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_2_3]))
            correct_score['0-4'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_0_4]))
            correct_score['1-4'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_1_4]))
            correct_score['2-4'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_2_4]))
            correct_score['3-4'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_3_4]))
            correct_score['0-0'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_0_0]))
            correct_score['1-1'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_1_1]))
            correct_score['2-2'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_2_2]))
            correct_score['3-3'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_3_3]))
            correct_score['4-4'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_4_4]))
            correct_score['other'] = str(self.get_odds(event_json[TX.Key.CORRECT_SCORE_OTHER]))
        return json.dumps(correct_score)

    def extract_half_full_score(self, event_json):
        half_full_score = {f'{first}{full}': '0' for first, full in product(['H', 'D', 'A'], repeat=2)}
        if event_json.get(TX.Key.HALF_FULL_SCORE_HH) is not None:
            half_full_score['HH'] = str(self.get_odds(event_json[TX.Key.HALF_FULL_SCORE_HH]))
            half_full_score['HD'] = str(self.get_odds(event_json[TX.Key.HALF_FULL_SCORE_HD]))
            half_full_score['HA'] = str(self.get_odds(event_json[TX.Key.HALF_FULL_SCORE_HA]))
            half_full_score['DH'] = str(self.get_odds(event_json[TX.Key.HALF_FULL_SCORE_DH]))
            half_full_score['DD'] = str(self.get_odds(event_json[TX.Key.HALF_FULL_SCORE_DD]))
            half_full_score['DA'] = str(self.get_odds(event_json[TX.Key.HALF_FULL_SCORE_DA]))
            half_full_score['AH'] = str(self.get_odds(event_json[TX.Key.HALF_FULL_SCORE_AH]))
            half_full_score['AD'] = str(self.get_odds(event_json[TX.Key.HALF_FULL_SCORE_AD]))
            half_full_score['AA'] = str(self.get_odds(event_json[TX.Key.HALF_FULL_SCORE_AA]))
        return json.dumps(half_full_score)

    def extract_score_sum(self, event_json):
        score_sum_full = {
            '0-1': '0',
            '2-3': '0',
            '4-6': '0',
            '7+': '0',
        }
        score_sum_first_half = {
            '0-1': '0',
            '2-3': '0',
            '4-6': '0',
            '7+': '0',
        }
        # ??????
        score_sum_full['0-1'] = str(self.get_odds(event_json[TX.Key.SCORE_SUM_0_1]))
        score_sum_full['2-3'] = str(self.get_odds(event_json[TX.Key.SCORE_SUM_2_3]))
        score_sum_full['4-6'] = str(self.get_odds(event_json[TX.Key.SCORE_SUM_4_6]))
        score_sum_full['7+'] = str(self.get_odds(event_json[TX.Key.SCORE_SUM_7_ABOVE]))
        # ??????
        score_sum_first_half['0-1'] = str(self.get_odds(event_json[TX.Key.SCORE_SUM_1ST_0_1]))
        score_sum_first_half['2-3'] = str(self.get_odds(event_json[TX.Key.SCORE_SUM_1ST_2_3]))
        score_sum_first_half['4-6'] = str(self.get_odds(event_json[TX.Key.SCORE_SUM_1ST_4_6]))
        score_sum_first_half['7+'] = str(self.get_odds(event_json[TX.Key.SCORE_SUM_1ST_7_ABOVE]))
        return score_sum_full, score_sum_first_half

    def convert_game_type(self, event_json):
        # ???????????????????????????????????? ????????????????????????
        scene = int(event_json[TX.Key.FULL_1ST_TYPE])
        kzdp = int(event_json[TX.Key.LIVE_TYPE])
        game_type_id = 99
        if scene == 11:
            game_type_id = 3
        elif scene == 12:
            game_type_id = 4
        elif scene == 13:
            game_type_id = 5
        elif scene == 14:
            game_type_id = 6
        elif kzdp == 2:
            if scene == 0:
                game_type_id = 7
            elif scene == 1:
                game_type_id = 8
            elif scene == 2:
                game_type_id = 9
        elif kzdp != 2:
            if scene == 0:
                game_type_id = 0
            elif scene == 1:
                game_type_id = 1
            elif scene == 2:
                game_type_id = 2
            elif scene == 8:
                game_type_id = 10
        return game_type_id

    def get_odds(self, odds):
        # ?????????????????????
        return odds if odds > 0 else 0

    def reverse_odds(self, spread, money_line, esre):
        # ??????
        tmp_line = spread.homeZF.line
        spread.homeZF.line = spread.awayZF.line
        spread.awayZF.line = tmp_line
        tmp_odds = spread.homeZF.odds
        spread.homeZF.odds = spread.awayZF.odds
        spread.awayZF.odds = tmp_odds
        # ??????
        tmp_odds = money_line.home
        money_line.home = money_line.away
        money_line.away = tmp_odds
        # ????????????
        if esre.let is protobuf_spec.whichTeam.home:
            esre.let = protobuf_spec.whichTeam.away
        else:
            esre.let = protobuf_spec.whichTeam.home
        tmp_odds = esre.home
        esre.home = esre.away
        esre.away = tmp_odds

    @step_logger('upload_data')
    async def upload_data(self, data):
        if not data or not data.aphdc:
            return
        succeed = True
        update_ids = [h.game_id for h in data.aphdc]
        self.step_log_json['update_counts'] = len(update_ids)
        self.step_log_json['update_ids'] = update_ids
        for handicaps in split_upload_bulk(data.aphdc, bulk_size=self._config['bulk_size']):
            bulk = protobuf_spec.ApHdcArr()
            bulk.aphdc.extend(handicaps)
            protobuf_data = bulk.SerializeToString()
            try:
                game_type = self.task_spec['game_type']
                if self.task_spec['category'] == 'pd':
                    game_type = f'{game_type}_pd'
                key = Mapping.routing_key_name[game_type]
                if self._config['env'] != 'production':
                    key = self._config['test_exchange']
                async with self.mq_channel_pool.acquire() as channel:
                    exchange = await channel.get_exchange(self._config['MQ_EXCHANGE'])
                    await exchange.publish(
                        routing_key=key,
                        message=aio_pika.Message(body=protobuf_data)
                    )
            except (aio_pika.AMQPException, asyncio.TimeoutError) as err:
                await self.logger.warning('??????protobuf?????????????????????API??????????????????: %s' % str(err), extra={'step': 'upload'})
                succeed = False
        if not succeed:
            self.task_failed = True
            await self.logger.error(f'{self.account} {self.name} ???????????????MQ??????', extra={'step': 'upload'})
            self.step_log_json['error'] = '???????????????MQ??????'
