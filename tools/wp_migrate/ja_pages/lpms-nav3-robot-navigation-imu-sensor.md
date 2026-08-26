# LPMS-NAV3

## LPMS-NAV3: ロボット・ナビゲーション向け単軸モーションセンサー

|  |  |
| --- | --- |
| ![LPMS-NAV3-TTL](2604_LPMS-NAV3-TTL.png){width=100%} | ![LPMS-NAV3-RS232](L2604_PMS-NAV3-RS232.png){width=100%} |
| **LPMS-NAV3-TTL** | **LPMS-NAV3-RS232** |


|  |  |
| --- | --- |
| ![LPMS-NAV3-RS485](2604_LPMS-NAV3-RS485.png){width=100%} | ![LPMS-NAV3-CAN](LPMS-NAV3-CAN_1024x683.png){width=100%} |
| **LPMS-NAV3-RS485** | **LPMS-NAV3-CAN** |


### 製品説明

LPMS-NAV3は、RS232/TTL/RS485/CAN/RS422通信インターフェースを備えた6軸の高性能慣性計測装置（IMU）です。

3軸加速度センサー/ジャイロスコープと、追加の高精度1軸ジャイロスコープの組み合わせにより、正確な相対方位情報を算出します。特に自動車、移動ロボット、無人搬送車（AGV）の用途を想定して開発されたユニットです。

センサーは、IP67準拠の頑丈なアルミニウム筐体に収められています。センサーの機能とパラメーターは、当社のLPMS-Control2ソフトウェア（サポートページからダウンロード可能）で設定できます。

### ダウンロード

（[LPMS-NAV3\_EN](/api/v1/website/assets/260424_LPMS-NAV3_EN.pdf)、[LPMS-NAV3\_JP](/api/v1/website/assets/260424_LPMS-NAV3_JP.pdf)）

[3Dメカニカルファイル](/api/v1/website/assets/LPMS-NAV3-3D-files.zip)

[LPMSドキュメントポータル](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1100611840/LPMS+Documentation)

[ソフトウェアダウンロード](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1138294814/LPMS+Data+Acquisition+Software)

### 仕様

|  |  |  |  |  |  |
| --- | --- | --- | --- | --- | --- |
| 型番 | **LPMS-NAV3  -TTL** | **LPMS-NAV3  -RS232** | **LPMS-NAV3  -RS485** | **LPMS-NAV3  -CAN** | **LPMS-NAV3  -RS422** |
| オイラー角範囲 | ロール: ±180°、ピッチ: ±90°、ヨー: ±180° | | | | |
| 分解能 | 0.01° | | | | |
| 出力データ形式 | 生データ/オイラー角/クォータニオン/線形加速度/温度 | | | | |
| 内部サンプリングレート | 500Hz | | | | |
| 通信インターフェース | TTL（UART） | RS232 | RS485 | CAN+TTL | RS422 |
| 通信プロトコル | **LPBUS** | **LPBUS** | **LPBUS  /MODBUS** | **CANOpen  /SequentialCAN** | **LPBUS** |
| 最大データ更新レート | 500Hz | | | | |
| 加速度センサー範囲 | 3軸、±2/±4/±8/±16g、16ビット | | | | |
| ジャイロスコープ範囲 | X-Y軸、±125/±250/±500/±1000/±2000/±4000°/s、16ビット  Z軸、±400°/s、24ビット | | | | |
| ジャイロスコープ・ノイズ密度 | X-Y軸 0.005dps/√Hz | | | | |
| 消費電力 | 0.072  (0.006A@12V) | 0.084  (0.007A@12V) | 0.072  (0.006A@12V) | 0.096  (0.008A@12V) | 0.072  (0.006A@12V) |
| 動作温度範囲 | -20~80°C（ご要望により -40~80°C） | | | | |
| サイズ | 50 x 42 x 25 mm | | | | |
| 重量 | 106.8（±4）g | | | | |
| 電源 | 5V~18V DC | | | | |
| コネクター | M12 | | | | |
| 防水性能 | IP67 | | | | |

### ご注文

| 製品 | パッケージ内容 | 価格 |
| --- | --- | --- |
| LPMS-NAV3-TTL | LPMS-NAV3-TTLセンサー ×1  防水ケーブル ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-nav3-ttl-6-axis-imu-ahrs-with-ttl-serial-interface/)  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-NAV3-RS232 | LPMS-NAV3-RS232センサー ×1  防水ケーブル ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-nav3-rs232/)  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-NAV3-RS485 | LPMS-NAV3-RS485センサー ×1  防水ケーブル ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-nav3-rs485-motion-sensor-for-navigation-water-proof-housing-with-rs485-interface/)  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-NAV3-CAN | LPMS-NAV3-CANセンサー ×1  防水ケーブル ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-nav3-can-6-axis-imu-ahrs-with-can-bus-interface/)  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-NAV3-RS422 | LPMS-NAV3-RS422センサー ×1  防水ケーブル ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-nav3-rs422-6-axis-industrial-imu-with-rs422-interface/)  [代理店を探す](/ja/distributors-lp-research "代理店") |

![](LpmsNAV3-RS232_Box_1024_683_20210906.jpg)
