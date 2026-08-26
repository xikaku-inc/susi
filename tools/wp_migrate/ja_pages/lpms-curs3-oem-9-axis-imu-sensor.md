# LPMS-CURS3

## LPMS-CURS3: USB、CANバス、UART対応のOEM版9軸慣性計測装置（IMU）/AHRS

![](LPMS-CURS3-latest-1.png)

#### LPMS-CURS3

### 製品説明

LPMS-CURS3は、複数の通信インターフェースを備えた高性能・超小型の慣性計測装置（IMU）です。CANバス、USB、UARTを統合したLPMS-CURS3は、サイズとコストが重視される用途における機械・人体のモーション計測のどちらにも最適です。LPMS-CURS3は筐体なしで出荷され、お客様自身のデバイスへの組み込みに理想的です。

なお、LPMS-CURS3の全バージョンがUSB通信に対応していますが、ファームウェアが追加でサポートするのは（RS232、TTLシリアル、CANバスのうち）1つのインターフェースのみです。ご注文の際には、ご希望の通信方式をお知らせください。

本ユニットには32ビットのデジタルシグナルプロセッサーが搭載されており、すべての計算をリアルタイムにオンボードで実行できます。当社のセンサーフュージョン手法の詳細については、[IMUcoreの解説](/ja/blog/imucore-sensor-fusion)をご参照ください。

LPMS-CURS3のCANバスインターフェースは、より大規模なCANバスインフラへのセンサー接続を可能にします。最小構成のCANopen実装と、カスタマイズ可能なシーケンシャルCANメッセージ形式をサポートしています。CANバス経由で送信する計測データの内容は、LPMS-Control2ソフトウェアで自由に設定できます。センサーの転送レート設定に応じて、最大500Hzのデータレートを実現します。

### ダウンロード

フライヤー（[LPMS-CURS3\_EN](/api/v1/website/assets/20251016_LPMS-CURS3_EN.pdf)、[LPMS-CURS3\_JP](/api/v1/website/assets/20251016_LPMS-CURS3_JP.pdf)）

[3Dメカニカルモデル](/api/v1/website/assets/lpms_curs3-3D-model-file.zip)

[LPMSドキュメントポータル](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1100611840/LPMS+Documentation)

[ソフトウェアダウンロード](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1138294814/LPMS+Data+Acquisition+Software)

### 仕様

|  |  |  |  |
| --- | --- | --- | --- |
| 型番 | **LPMS-CURS3-CAN** | **LPMS-CURS3-RS232** | **LPMS-CURS3-TTL** |
| オイラー角範囲 | ロール: ±180°、ピッチ: ±90°、ヨー: ±180° | | |
| 分解能 | 0.01° | | |
| 精度 | < 0.5°（静的）、< 2° RMS（動的） | | |
| 出力データ形式 | 生データ/オイラー角/クォータニオン/線形加速度/気圧/温度 | | |
| 内部サンプリングレート | 500Hz | | |
| 通信インターフェース | CANバス | RS232 | TTL（UART） |
| 最大ボーレート | 1Mbps | 921600bps | 921600bps |
| 通信プロトコル | CANOpen / SequentialCAN | LPBUS/ASCII | LPBUS/ASCII |
| 最大データ更新レート | 500Hz | | |
| 加速度センサー範囲 | 3軸、±2/±4/±8/±16g、16ビット | | |
| ジャイロスコープ範囲 | 3軸、±125/±250/±500/±1000/±2000/±4000°/s、16ビット | | |
| ジャイロスコープ・ノイズ密度 | 0.005dps/√Hz | | |
| 地磁気センサー範囲 | 3軸、±2/±8gauss、16ビット | | |
| 気圧センサー | 300~1100hPa | | |
| 消費電力 | <135mW@5V | <110mW@5V | <90mW@5V |
| 動作温度範囲 | -20~80°C | | |
| サイズ | 22x28x7.65 | | |
| 重量 | 4g | | |
| 電源 | 5V~18V DC | | |
| コネクター | BM08B 1.25mm | Micro USB-B | | |

### ご注文

| 製品 | パッケージ内容 | 価格 |
| --- | --- | --- |
| LPMS-CURS3-CAN | LPMS-CURS3-CANセンサー ×1  ケーブル（1.27mmピッチコネクター） ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-curs3-can-oem-version-9-axis-inertial-measurement-unit-imu-with-usb-and-can-bus/)  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-CURS3-RS232 | LPMS-CURS3-RS232センサー ×1  ケーブル（1.27mmピッチコネクター） ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-curs3-rs232-oem-version-9-axis-inertial-measurement-unit-imu-with-usb-and-rs232-connectivity/)  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-CURS3-TTL | LPMS-CURS3-TTLセンサー ×1  ケーブル（1.27mmピッチコネクター） ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-curs3-ttl-oem-version-9-axis-inertial-measurement-unit-imu-with-usb-and-ttl/)  [代理店を探す](/ja/distributors-lp-research "代理店") |

![](LpmsCURS3_Box_1024_683_20210111.jpg)
