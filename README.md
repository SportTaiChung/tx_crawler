# tx crawler

## 網站

網站首頁: 
爬蟲戳的API: 

## 爬蟲範圍

| 球類\玩法 | 早盤                 | 今天盤               | 團隊總得分           |
|-----------|----------------------|----------------------|----------------------|
| 棒球      | 全場、HRE、第一局 | 全場、HRE、第一局 | HRE放全場、上半場   |
| 籃球      | 全場、上半場      | 全場、上半場      | 全場放2nd、上半場 |
| 冰球      | 全場、上半場      | 全場、上半場      | 全場、上半場      |
| 美式足球  | 全場、上半場      | 全場、上半場      | 全場、上半場      |


## 專案環境

```shell
~> pip install pipenv
# 安裝相依套件
tx_crawler> pipenv install
# 進入virtualenv
tx_crawler> pipenv shell
# 執行
(tx_crawler) tx_crawler> python main.py
```

## 正式機環境

### 資料夾建立

```shell
~>mkdir log supervisor
supervisor>mkdir conf.d run log
tx_crawler>cp supervisor/*.conf $SUPERVISOR_DIR/conf.d/
```

### supervisor常用指令

```shell
# 進入virtualenv
tx_crawler> pipenv shell
tx_crawler> supervisord -c $SUPERVISOR_CONFIG
tx_crawler> supervisorctl -c $SUPERVISOR_CONFIG
# 確認爬蟲狀態
supervisorctl> status
tx_crawler                     RUNNING   pid 7252, uptime 0:01:38
# 更新設定檔
supervisorctl> update
tx_crawler: stopped
tx_crawler: updated process group
# 啟動
supervisorctl> start tx_crawler
# 重啟
supervisorctl> restart tx_crawler
# 停止
supervisorctl> stop tx_crawler
```