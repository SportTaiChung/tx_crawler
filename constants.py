# coding: utf-8
from enum import Enum


DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36 Edg/87.0.664.75'


class Source(Enum):
    TX = 'TX'


class Site(Enum):
    THA = 'tha'
    LEO = 'leo'


class GameType(Enum):
    # baseball not used in protobuf game class
    baseball = 'baseball'
    mlb = 'mlb'    # 美棒
    npb = 'npb'    # 日棒
    cpbl = 'cpbl'  # 台棒
    kbo = 'kbo'    # 韓棒和其他
    basketball = 'basketball'  # NBA
    otherbasketball = 'otherbasketball'  # 其他非NBA籃球
    tennis = 'tennis'
    hockey = 'hockey'
    football = 'football'
    eSport = 'eSport'
    soccer = 'soccer'
    UCL = 'UCL'  # 歐洲冠軍足球
    pingpong = 'other'
    volleyball = 'other'
    other = 'other'


class GameCategory(Enum):
    ZF = 'zf'  # spread 讓分
    DS = 'ds'  # total 大小
    DE = 'de'  # money line 獨贏
    ESRE = 'esre'  # 一輸二贏
    SD = 'sd'  # parity 單雙數


class PlayType(Enum):
    TODAY = 'today'
    EARLY = 'early'
    TEAM_TOTAL = 'team totals'
    LIVE = 'live'
    TEAM_TOTAL_LIVE = 'team totals live'


class Period(Enum):
    FULL = 'full'
    FIRST_HALF = '1st half'
    SECOND_HALF = '2nd half'
    LIVE = 'live'
    LIVE_FULL = 'live full'
    LIVE_FIRST_HALF = 'live 1st half'
    # 波膽
    CORRECT_SCORE = 'pd full'
    CORRECT_SCORE_1ST_HALF = 'pd 1st half'
    CORRECT_SCORE_2ND_HALF = 'pd 2nd half'
    CORRECT_SCORE_LIVE = 'pd live full'
    CORRECT_SCORE_LIVE_1ST_HALF = 'pd live 1st half'
    CORRECT_SCORE_LIVE_2ND_HALF = 'pd live 2nd half'
    # 半全場
    HALF_FULL_SCORE = 'hf full'
    HALF_FULL_SCORE_LIVE = 'hf live full'
    # 入球數
    SCORE_SUM = 'tg full'
    SCORE_SUM_1ST_HALF = 'tg 1st half'
    SCORE_SUM_LIVE = 'tg live full'
    SCORE_SUM_LIVE_1ST_HALF = 'tg live 1st half'
    # 多玩法
    MULTI = 'multi'


class TX:
    class Key:
        SPORT_EVENT_INFO = 'listBallCountryMenu'
        SPORT_TYPE_ID = 'Typid'
        SPORT_TYPE = 'Typ'
        SPORT_NAME = 'TypName'
        BALL_TYPE = 'Balltyp'
        IS_WORLD_CUP = 'isWorldCup'
        CATEGORY_DATA = 'gameData'
        CATEGORY_ID = 'Typid'
        EVENT_LIST = 'BallData'
        CORRECT_SCORE_EVENT_LIST = 'CorrectScore'
        HALF_FULL_SCORE_EVENT_LIST = 'HalfTheAudience'
        SCORE_SUM_EVENT_LIST = 'Goals'
        ERROR_MESSAGE = 'ErrorString'
        EMPTY_EVENT_LIST = 'NoRefData'
        TOTAL_PAGE_NUM = 'PageTotalRecords'
        TOTAL_EVENT_COUNT = 'Count'
        # event keys
        EVENT_SPORT_TYPE = 's_BallSx'
        EVENT_SPORT_NAME = 's_BallName'
        EVENT_LIVE = 'isOpenLivePlay'
        EVENT_LIVE_PERIOD = 's_ZQMidfielder'
        EVENT_LIVE_TIME = 's_ZQInPlayTime'
        EVENT_LEAGUE_NAME_WITH_POSTFIX = 's_Alliance'
        EVENT_TIME = 'dtm_GameDate'
        TEAM_ORDER = 's_Zc'
        TEAM_A = 's_TeamA'
        TEAM_B = 's_TeamB'
        EVENT_ID = 's_ZbMatchID'
        EVENT_ID_GP = 's_GPID'
        EVENT_ID_1 = 's_ID_1'
        EVENT_SCORE_HOME = 's_RZJZF'
        EVENT_SCORE_AWAY = 's_RYJZF'
        EVENT_RED_CARD_HOME = 'i_RedCardA_1'
        EVENT_RED_CARD_AWAY = 'i_RedCardB_1'
        # 讓分
        SPREAD_ADVANCED_TEAM = 'i_RRF3_1'
        SPREAD_LINE = 's_RFPK0_1'
        SPREAD_OTHER_ADVANCED_TEAM = 's_RFPK1_1'
        SPREAD_LINE_OTHER_VALUE = 's_RFPK2_1'
        SPREAD_HOME = 'dbl_RF_Y_PL_1'
        SPREAD_AWAY = 'dbl_RF_Z_PL_1'
        SPREAD_1ST_ADVANCED_TEAM = 'i_RRF3_2'
        SPREAD_1ST_LINE = 's_RFPK0_2'
        SPREAD_1ST_OTHER_ADVANCED_TEAM = 's_RFPK1_2'
        SPREAD_1ST_LINE_OTHER_VALUE = 's_RFPK2_2'
        SPREAD_1ST_HOME = 'dbl_RF_Y_PL_2'
        SPREAD_1ST_AWAY = 'dbl_RF_Z_PL_2'
        # 大小
        TOTAL_LINE = 's_DXPK0_1'
        TOTAL_LINE_SIGN = 's_DXPK1_1'
        TOTAL_LINE_OTHER_VALUE = 's_DXPK2_1'
        TOTAL_OVER = 'dbl_DX_D_PL_1'
        TOTAL_UNDER = 'dbl_DX_X_PL_1'
        TOTAL_1ST_LINE = 's_DXPK0_2'
        TOTAL_1ST_LINE_SIGN = 's_DXPK1_2'
        TOTAL_1ST_LINE_OTHER_VALUE = 's_DXPK2_2'
        TOTAL_1ST_OVER = 'dbl_DX_X_PL_2'
        TOTAL_1ST_UNDER = 'dbl_DX_D_PL_2'
        # 獨贏
        MONEY_LINE_HOME = 'dbl_DY_Y_PL_1'
        MONEY_LINE_AWAY = 'dbl_DY_Z_PL_1'
        MONEY_LINE_DRAW = 'dbl_DY_H_PL_1'
        MONEY_LINE_1ST_HOME = 'dbl_DY_Y_PL_2'
        MONEY_LINE_1ST_AWAY = 'dbl_DY_Z_PL_2'
        MONEY_LINE_1ST_DRAW = 'dbl_DY_H_PL_2'
        # 讓分一輸二贏
        ESRE_HOME = 'dbl_YSEY_Y_PL_1'
        ESRE_AWAY = 'dbl_YSEY_Z_PL_1'
        ESRE_1ST_HOME = 'dbl_YSEY_Y_PL_2'
        ESRE_1ST_AWAY = 'dbl_YSEY_Z_PL_2'
        # 單雙
        PARITY_ODD = 'dbl_DS_S_PL_1'
        PARITY_EVEN = 'dbl_DS_D_PL_1'
        PARITY_1ST_ODD = 'dbl_DS_S_PL_2'
        PARITY_1ST_EVEN = 'dbl_DS_D_PL_2'
        # 額外盤口
        FULL_1ST_TYPE = 's_Scene_1'
        LIVE_TYPE = 's_Kzdp'
        SECOND_HALF = 's_Scene_2'
        # 搶首
        FIRST_GOAL_HOME = 'dbl_QSF_Z_PL_1'
        FIRST_GOAL_AWAY = 'dbl_QSF_Y_PL_1'
        # 搶尾
        LAST_GOAL_HOME = 'dbl_QWF_Z_PL_1'
        LAST_GOAL_AWAY = 'dbl_QWF_Y_PL_1'
        # 單節最高分
        SINGLE_SET_HIGHEST_SCORE_HOME = 'dbl_DJZG_Z_PL_1'
        SINGLE_SET_HIGHEST_SCORE_AWAY = 'dbl_DJZG_Y_PL_1'
        # 波膽
        # 主隊
        CORRECT_SCORE_1_0 = 's_Z10'
        CORRECT_SCORE_2_0 = 's_Z20'
        CORRECT_SCORE_2_1 = 's_Z21'
        CORRECT_SCORE_3_0 = 's_Z30'
        CORRECT_SCORE_3_1 = 's_Z31'
        CORRECT_SCORE_3_2 = 's_Z32'
        CORRECT_SCORE_4_0 = 's_Z40'
        CORRECT_SCORE_4_1 = 's_Z41'
        CORRECT_SCORE_4_2 = 's_Z42'
        CORRECT_SCORE_4_3 = 's_Z43'
        # 客隊
        CORRECT_SCORE_0_1 = 's_K10'
        CORRECT_SCORE_0_2 = 's_K20'
        CORRECT_SCORE_1_2 = 's_K21'
        CORRECT_SCORE_0_3 = 's_K30'
        CORRECT_SCORE_1_3 = 's_K31'
        CORRECT_SCORE_2_3 = 's_K32'
        CORRECT_SCORE_0_4 = 's_K40'
        CORRECT_SCORE_1_4 = 's_K41'
        CORRECT_SCORE_2_4 = 's_K42'
        CORRECT_SCORE_3_4 = 's_K43'
        # 和局
        CORRECT_SCORE_0_0 = 's_Z00'
        CORRECT_SCORE_1_1 = 's_Z11'
        CORRECT_SCORE_2_2 = 's_Z22'
        CORRECT_SCORE_3_3 = 's_Z33'
        CORRECT_SCORE_4_4 = 's_Z44'
        # 其他
        CORRECT_SCORE_OTHER = 's_Z55'
        # 半全場
        # 主隊(H/Z) 和局(D/H) 客(A/K)
        HALF_FULL_SCORE_HH = 's_BDZZ'
        HALF_FULL_SCORE_HD = 's_BDZH'
        HALF_FULL_SCORE_HA = 's_BDZK'
        HALF_FULL_SCORE_DH = 's_BDHZ'
        HALF_FULL_SCORE_DD = 's_BDHH'
        HALF_FULL_SCORE_DA = 's_BDHK'
        HALF_FULL_SCORE_AH = 's_BDKZ'
        HALF_FULL_SCORE_AD = 's_BDKH'
        HALF_FULL_SCORE_AA = 's_BDKK'
        # 入球數
        SCORE_SUM_0_1 = 's_RQS_01_1'
        SCORE_SUM_2_3 = 's_RQS_23_1'
        SCORE_SUM_4_6 = 's_RQS_46_1'
        SCORE_SUM_7_ABOVE = 's_RQS_7_1'
        SCORE_SUM_1ST_0_1 = 's_RQS_01_2'
        SCORE_SUM_1ST_2_3 = 's_RQS_23_2'
        SCORE_SUM_1ST_4_6 = 's_RQS_46_2'
        SCORE_SUM_1ST_7_ABOVE = 's_RQS_7_2'
        # alert
        ALERT_TYPE = 'alertType'
        LOGOUT_TYPE_ID = 'strLogOutType'
        IS_LOGOUT = 'isKict'

    class Pos:
        class Lang:
            TRADITIONAL_CHINESE = 0
            SIMPLIFIED_CHINESE = 1
            ENGLISH = 2
            VIETNAMESE = 3
            THAI = 4

        class Encryption:
            DATA = 0
            INFO = 1
            TYPE = 2
            HASH_KEY = 3

    class Value:
        LOGOUT_TYPE = 'backLogOutPage'
        LOGOUT_ALERT_IDS = ['4', '6', '7', '9', '11', '12', '14', '15', '']
        BANNED_ALERT_IDS = ['1', '2', '3', '5', '8', '13']
        SITE_MAINTAIN_ALERT_ID = '10'
        WORLD_CUP = 4

        class SportType(Enum):
            EUROPE_FIVE_SOCCER_LEAGUE = 'wdls'
            SOCCER = 'zq'
            BASEBALL = 'baseball'
            BASKETBALL = 'lq'
            TENNIS = 'wq'
            HOCKEY = 'bq'
            OTHER = 'ot'  # OTHER 包含排球、手球、撞球、桌球、羽球、電競
            SOCCER_OLYMPIC = 'zqOlympic'  # 足球奧運

            @staticmethod
            def get_sport_type(game_type):
                return Mapping.sport_type[game_type]

        class BallType(Enum):
            EUROPE_FIVE_SOCCER_LEAGUE = ''
            SOCCER = 'b_zq'
            SOCCER_CORRECT_SCORE = '4'
            SOCCER_SCORE_SUM = '5'
            SOCCER_FIRST_HALF_RESULT = '6'
            BASEBALL = 'b_bangq'
            BASKETBALL = 'b_lq'
            TENNIS = 'b_wq'
            HOCKEY = 'b_bq'
            VOLLEYBALL = 'b_pq'
            HANDBALL = 'b_sq'
            POOL = 'b_zhuangq'  # 撞球
            PINGPONG = 'b_ppq'
            BADMINTON = 'b_ymq'
            E_SPORT = 'b_dzjj'

            @staticmethod
            def get_ball_type(game_type, category):
                if category == 'pd':
                    return TX.Value.BallType.SOCCER_CORRECT_SCORE
                elif category == 'tg':
                    return TX.Value.BallType.SOCCER_SCORE_SUM
                elif category == 'hf':
                    return TX.Value.BallType.SOCCER_FIRST_HALF_RESULT
                elif game_type == 'pingpong':
                    return TX.Value.BallType.PINGPONG
                elif game_type == 'volleyball':
                    return TX.Value.BallType.VOLLEYBALL
                return Mapping.ball_type[GameType[game_type]]

            def get_id(self):
                return Mapping.ball_type_id[self]

        class BallTypeID(Enum):
            EUROPE_FIVE_SOCCER_LEAGUE = 'wdls'
            SOCCER = '10'
            BASEBALL = '13'
            BASKETBALL = '6'
            TENNIS = '9'
            HOCKEY = '5'
            VOLLEYBALL = '234'
            HANDBALL = '236'
            POOL = '237'  # 撞球
            PINGPONG = '235'
            BADMINTON = '233'
            E_SPORT = '238'

        class SortType(Enum):
            TIME_SORT = 'timesort'
            HOT_SORT = 'hotsort'

        class Scene(Enum):
            ALL_CATEGORY = 'gameall_country'
            ALL = 'all'
            SECOND_HALF = '2'
            LIVE = '3'  # 走地
            PARLAY = '7'  # 過關
            SPECIAL_BET = '9'  # 特別投注
            SPECIAL_15_MIN = '10'  # 特定15分
            FULL_FIRST_HALF = '11'  # 單式，全場、上半場
            SET = '12'  # 單節
            TEAM_TOTAL = '15'
            PINGPONG_VOLLEYBALL_SET = '20'
            TENNIS_SET = '21'
            FIRST_BLOOD = '22'
            KILL_HERO = '23'
            FIRST_LAST_POINT = '24'  # 首尾分

            @staticmethod
            def get_scene(play_type):
                return Mapping.scene.get(play_type, TX.Value.Scene.ALL_CATEGORY)

        class CategoryID(Enum):
            ALL = '0'
            SOCCER_ALL = '10'
            BASEBALL_ALL = '207'
            BASKETBALL_NBA = '22'
            BASKETBALL_NCAA = '212'
            ASIA = '117'  # basketball, volleyball
            EUROPE = '161'  # basketball, hockey, volleyball
            BASKETBALL_IFM = '118'  # 國際友宜賽
            BASKETBALL_MIXED_PARLAY = '0%2C22%2C212%2C117%2C161'  # 綜合過關
            TENNIS_ATP = '60'
            TENNIS_ITF_MAN = '108'
            TENNIS_ITF_WOMAN = '109'
            HOCKEY_NHL = '23'
            HOCKEY_MIXED_PARLAY = '0%2C23%2C161'
            HANDBALL_WORLD = '194'
            POOL_SNOOKER = '242'
            E_SPORT_LOL = '244'
            E_SPORT_CS = '291'

            @staticmethod
            def get_id(play_type):
                return Mapping.category_id.get(play_type, TX.Value.CategoryID.ALL)

        class AdvancedTeam(Enum):
            HOME = 1
            AWAY = 0

        class LivePeriod(Enum):
            NOT_START = 0
            FIRST_HALF = 1
            SECOND_HALF = 2
            INTERMISSION = 3


class Mapping:
    logout_code = {
        '1': '您的帳號存在異常！',
        '2': '您的操作過於頻繁！',
        '3': '系統檢測到異常，請重新訪問！',
        '4': '您的帳號已登出！',
        '5': '訪問受限！',
        '6': '資料讀取失敗！',
        '7': '偵測到重複登入，已將您登出',
        '您被強迫下線，您的帳戶在其它位置登入！'
        '8': '登入帳號異常！',
        '9': '網路異常，資料讀取失敗！',
        '10': '系統升級中，請稍候重進……',
        '11': '系統檢測到異常，請重新訪問！',
        '12': '網絡異常！',
        '13': '您的帳號已被鎖定',
        '14': '您已登出！',
        '15': '資料讀取失敗！',
        '': '您已登出！'
    }
    ball_type = {
        GameType.soccer: TX.Value.BallType.SOCCER,
        GameType.basketball: TX.Value.BallType.BASKETBALL,
        GameType.baseball: TX.Value.BallType.BASEBALL,
        GameType.tennis: TX.Value.BallType.TENNIS,
        GameType.hockey: TX.Value.BallType.HOCKEY,
        GameType.eSport: TX.Value.BallType.E_SPORT,
        GameType.pingpong: TX.Value.BallType.PINGPONG,
        GameType.volleyball: TX.Value.BallType.VOLLEYBALL
    }
    ball_type_id = {
        TX.Value.BallType.EUROPE_FIVE_SOCCER_LEAGUE: TX.Value.BallTypeID.EUROPE_FIVE_SOCCER_LEAGUE,
        TX.Value.BallType.SOCCER: TX.Value.BallTypeID.SOCCER,
        TX.Value.BallType.SOCCER_CORRECT_SCORE: TX.Value.BallTypeID.SOCCER,
        TX.Value.BallType.SOCCER_SCORE_SUM: TX.Value.BallTypeID.SOCCER,
        TX.Value.BallType.SOCCER_FIRST_HALF_RESULT: TX.Value.BallTypeID.SOCCER,
        TX.Value.BallType.BASEBALL: TX.Value.BallTypeID.BASEBALL,
        TX.Value.BallType.BASKETBALL: TX.Value.BallTypeID.BASKETBALL,
        TX.Value.BallType.TENNIS: TX.Value.BallTypeID.TENNIS,
        TX.Value.BallType.HOCKEY: TX.Value.BallTypeID.HOCKEY,
        TX.Value.BallType.VOLLEYBALL: TX.Value.BallTypeID.VOLLEYBALL,
        TX.Value.BallType.HANDBALL: TX.Value.BallTypeID.HANDBALL,
        TX.Value.BallType.POOL: TX.Value.BallTypeID.POOL,  # 撞球
        TX.Value.BallType.PINGPONG: TX.Value.BallTypeID.PINGPONG,
        TX.Value.BallType.BADMINTON: TX.Value.BallTypeID.BADMINTON,
        TX.Value.BallType.E_SPORT: TX.Value.BallTypeID.E_SPORT
    }
    sport_type = {
        'eu_5_soccer_leagues': TX.Value.SportType.EUROPE_FIVE_SOCCER_LEAGUE,
        'soccer': TX.Value.SportType.SOCCER,
        'baseball': TX.Value.SportType.BASEBALL,
        'basketball': TX.Value.SportType.BASKETBALL,
        'tennis': TX.Value.SportType.TENNIS,
        'hockey': TX.Value.SportType.HOCKEY,
        'volleyball': TX.Value.SportType.OTHER,
        'handball': TX.Value.SportType.OTHER,
        'pool': TX.Value.SportType.OTHER,  # 撞球
        'pingpong': TX.Value.SportType.OTHER,
        'badminton': TX.Value.SportType.OTHER,
        'eSport': TX.Value.SportType.OTHER,
        'soccer_olympic': TX.Value.SportType.SOCCER_OLYMPIC  # 足球奧運
    }
    scene = {
        'all_category': TX.Value.Scene.ALL_CATEGORY,
        'all': TX.Value.Scene.ALL,
        '2nd': TX.Value.Scene.SECOND_HALF,
        'live': TX.Value.Scene.LIVE,  # 走地
        'parlay': TX.Value.Scene.PARLAY,  # 過關
        'special': TX.Value.Scene.SPECIAL_BET,  # 特別投注
        '15min': TX.Value.Scene.SPECIAL_15_MIN,  # 特定15分
        'full': TX.Value.Scene.FULL_FIRST_HALF,  # 單式，全場、上半場
        'set': TX.Value.Scene.SET,  # 單節
        'tennis_set': TX.Value.Scene.TENNIS_SET,
        'pingpong_volleyball_set': TX.Value.Scene.PINGPONG_VOLLEYBALL_SET,
        'team total': TX.Value.Scene.TEAM_TOTAL,
        'first_last_point': TX.Value.Scene.FIRST_LAST_POINT,  # 首尾分
        'first_blood': TX.Value.Scene.FIRST_BLOOD,
        'kill_hero': TX.Value.Scene.KILL_HERO
    }
    category_id = {
        'all': TX.Value.CategoryID.ALL,
        'soccer': TX.Value.CategoryID.SOCCER_ALL,
        'baseball': TX.Value.CategoryID.BASEBALL_ALL,
        'nba': TX.Value.CategoryID.BASKETBALL_NBA,
        'ncaa': TX.Value.CategoryID.BASKETBALL_NCAA,
        'asia': TX.Value.CategoryID.ASIA,  # basketball, volleyball
        'europe': TX.Value.CategoryID.EUROPE,  # basketball, hockey, volleyball
        'ifm': TX.Value.CategoryID.BASKETBALL_IFM,  # 國際友宜賽
        'mixed_parlay': TX.Value.CategoryID.BASKETBALL_MIXED_PARLAY,  # 綜合過關
        'atp': TX.Value.CategoryID.TENNIS_ATP,
        'itf_man': TX.Value.CategoryID.TENNIS_ITF_MAN,
        'itf_woman': TX.Value.CategoryID.TENNIS_ITF_WOMAN,
        'nhl': TX.Value.CategoryID.HOCKEY_NHL,
        'hockey_mixed_parlay': TX.Value.CategoryID.HOCKEY_MIXED_PARLAY,
        'handball': TX.Value.CategoryID.HANDBALL_WORLD,
        'snooker': TX.Value.CategoryID.POOL_SNOOKER,
        'lol': TX.Value.CategoryID.E_SPORT_LOL,
        'cs': TX.Value.CategoryID.E_SPORT_CS,
    }
    game_class = {
        'wdls': GameType.soccer.value,
        'soccer': GameType.soccer.value,
        'baseball': GameType.baseball.value,
        'basketball': GameType.basketball,
        'tennis': GameType.tennis,
        'hockey': GameType.hockey,
        'eSport': GameType.eSport,
        'football': GameType.football,
        'other': GameType.other,  # OTHER 包含排球、手球、撞球、桌球、羽球、電競
        'zqOlympic': GameType.soccer  # 足球奧運
    }
    league_postfix = {
        # 網球
        '第一盤': {
            'cn': '-第一盘获胜者',
            'en': '-1st Set Winner'
        },
        '第二盤': {
            'cn': '-第二盘获胜者',
            'en': '-2nd Set Winner'
        },
        '第三盤': {
            'cn': '-第三盘获胜者',
            'en': '-3rd Set Winner'
        },
        # 排球&乒乓球
        '第一局': {
            'cn': '-第一局',
            'en': '-1st Set'
        },
        '第二局': {
            'cn': '-第二局',
            'en': '-2nd Set'
        },
        '第三局': {
            'cn': '-第三局',
            'en': '-3rd Set'
        },
        '第四局': {
            'cn': '-第四局',
            'en': '-4st Set'
        },
        '第五局': {
            'cn': '-第五局',
            'en': '-5nd Set'
        },
        '第六局': {
            'cn': '-第六局',
            'en': '-6rd Set'
        },
        '第七局': {
            'cn': '-第七局',
            'en': '-7rd Set'
        },
        # 電競
        '擊殺英雄總數(第一局)': {
            'cn': '-击杀英雄总数(第一局)',
            'en': '-TOTAL KILL THE HERO (1st SET)'
        },
        '擊殺英雄總數(第二局)': {
            'cn': '-击杀英雄总数(第二局)',
            'en': '-TOTAL KILL THE HERO (2nd SET)'
        },
        '擊殺英雄總數(第三局)': {
            'cn': '-击杀英雄总数(第三局)',
            'en': '-TOTAL KILL THE HERO (3rd SET)'
        },
        '獲得第一滴血(第一局)': {
            'cn': '-获得第一滴血(第一局)',
            'en': '-DRAW FIRST BLOOD (1st SET)'
        },
        '獲得第一滴血(第二局)': {
            'cn': '-获得第一滴血(第二局)',
            'en': '-DRAW FIRST BLOOD (2nd SET)'
        },
        '獲得第一滴血(第三局)': {
            'cn': '-获得第一滴血(第三局)',
            'en': '-DRAW FIRST BLOOD (3rd SET)'
        },
        '對戰時間(第一局)': {
            'cn': '-对战时间(第一局)',
            'en': '-DURATION (1st SET)'
        },
        '對戰時間(第二局)': {
            'cn': '-对战时间(第二局)',
            'en': '-DURATION (2nd SET)'
        },
        '對戰時間(第三局)': {
            'cn': '-对战时间(第三局)',
            'en': '-DURATION (3rd SET)'
        }
    }
    game_id_prefix = {
        '籃球': '14',
        '兵乓球': '16',
        '排球': '21'
    }
    exchange_name = {
        'soccer': 'TX_SC',
        'soccer_pd': 'TX_SC_PD',
        'baseball': 'TX_BS',
        'basketball': 'TX_BK',
        'tennis': 'TX_TN',
        'hockey': 'TX_HC',
        'football': 'TX_FB',
        'pingpong': 'TX_PP',
        'volleyball': 'TX_VL',
        'eSport': 'TX_ES'
    }
    live_time_prefix = {
        TX.Value.LivePeriod.NOT_START: '0',
        TX.Value.LivePeriod.FIRST_HALF: '上',
        TX.Value.LivePeriod.SECOND_HALF: '下',
        TX.Value.LivePeriod.INTERMISSION: '中場'
    }
    event_list_key = {
        'pd': TX.Key.CORRECT_SCORE_EVENT_LIST,
        'tg': TX.Key.SCORE_SUM_EVENT_LIST,
        'hf': TX.Key.HALF_FULL_SCORE_EVENT_LIST
    }
