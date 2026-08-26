# LPMS-IG1

## LPMS-IG1シリーズ: USB/CAN/RS232/RS485対応の高精度9軸慣性計測装置（IMU）/AHRS

|  |  |
| --- | --- |
| ![高精度9軸IMU](LpmsIG1-RS232_1024_683_20190214.jpg){width=100%} | ![高精度9軸IMU](LpmsIG1-CAN_1024_683_20190214.jpg){width=100%} |
| **LPMS-IG1 RS232** | **LPMS-IG1 CAN** |


|  |  |
| --- | --- |
| ![LPMS-IG1 RS485 IMU 高精度姿勢センサー](LpmsIG1-RS485_1024_683_20200604.jpg){width=100%} |  |
| **LPMS-IG1 RS485** |  |


### 製品説明

LP-ResearchモーションセンサーLPMS-IG1シリーズは、USB/CAN/RS232/RS485接続に対応した、IP67準拠筐体（防水）の高精度9軸慣性計測装置（IMU）/AHRSシステムです。

このシリーズは非常に汎用性が高く、高精度・高速な姿勢計測を行います。3つの独立した低ノイズ1軸ジャイロスコープの出力を、3軸加速度センサーおよび地磁気センサーのデータと融合することで、低ドリフト・低遅延の3D姿勢情報を実現しています。

低ノイズジャイロスコープの対応角速度は最大400dpsのため、最大2000dpsに対応する3軸ジャイロスコープを追加で搭載しています。姿勢データのソースとしてどちらのジャイロスコープを使用するかは、ユーザーが選択できます。

当社のセンサーフュージョン手法の詳細については、[IMUcoreの解説](/ja/blog/imucore-sensor-fusion)をご参照ください。また、IMUと車両オドメトリーデータの融合により、LPMS-IG1シリーズのセンサーをAGV・自動車用途のデッドレコニングセンサーとして使用するためのカスタムアルゴリズムもご提供しています。

LPMS-IG1シリーズは、USB通信に加え、オプションでCANバス、RS232またはRS485接続でホストに接続できます。ご注文の際には、ご希望のセンサー型番をご指定ください。

センサーの全パラメーターとデータ伝送オプションは、当社のIG1-Controlソフトウェアで制御できます。Windows/Linux PCや組み込みシステムとの直接連携のために、充実したライブラリサポートをご提供しています。

### ダウンロード

フライヤー（[LPMS-IG1\_EN](/api/v1/website/assets/202604-LPMS-IG1_EN.pdf)、[LPMS-IG1\_JP](/api/v1/website/assets/202604-LPMS-IG1_JP.pdf)）

[3Dメカニカルファイル](/api/v1/website/assets/20190909LpmsIg13DModel.zip)

[LPMSドキュメントポータル](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1100611840/LPMS+Documentation)

[ソフトウェアダウンロード](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1138294814/LPMS+Data+Acquisition+Software)

### 仕様

| 型番 | LPMS-IG1 RS232 | LPMS-IG1 CAN | LPMS-IG1 RS485 |
| --- | --- | --- | --- |
| インターフェース | USB + RS232 | USB + CANバス | USB + RS485 |
| 通信プロトコル | LP-BUS/ ASCII | LP-BUS/CANopen/  Sequential CAN | LP-BUS/ ASCII |
| サイズ | 51 x 45 x 24 mm | | |
| 重量 | V3: 74g、V4以降: 114.2g | | |
| 姿勢計測範囲 | ロール: ±180°、ピッチ: ±90°、ヨー: ±180° | | |
| 分解能 | < 0.01° | | |
| 加速度センサー | 3軸、±2 / ±4 / ±8 / ±16 g、16ビット | | |
| ジャイロスコープ（デュアル搭載） | ジャイロ#1: 3軸、±400 dps、24ビット、ジャイロ#2: 3軸、±1000 / ±2000 dps、16ビット | | |
| ジャイロスコープ・ノイズ密度 | #1: 0.002 dps/√Hz、#2: 0.004 dps/√Hz | | |
| 地磁気センサー | 3軸、±4 / ±8 / ±12 / ±16 gauss、16ビット | | |
| 精度 | < 0.3°（静的）、< 1° RMS（動的） | | |
| 静的姿勢安定性 | #1: 4 °/hour、#2: 6 °/hour | | |
| データ出力形式 | 生データ / オイラー角 / クォータニオン | | |
| データ出力レート | 5 ~ 500 Hz | | |
| 消費電力 | 0.216（0.018A@12 V） | 0.252（0.021A@12 V） | 0.24（0.02A@12 V） |
| 電源 | 5 V ~ 36 V DC | | |
| コネクター | M12 8ピン（SACC-DSI-MS-8CON-PG 9/0,5 SCO相当） | | |
| ハウジング | アルミニウム、IP67準拠 | | |
| 動作温度範囲 | -20 ~ +80 °C（ご要望により -40 ~ +80 °C） | | |
| ソフトウェア | IG1-Controlソフトウェア、C++ APIライブラリ | | |

### ご注文

| 製品 | パッケージ内容 | 価格 |
| --- | --- | --- |
| LPMS-IG1-RS232 | LPMS-IG1-RS232センサー ×1  防水ケーブル ×2  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://www.zenshin-tech.com/product/lpms-ig1-rs232/ "オンラインで注文")  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-IG1-CAN | LPMS-IG1-CANセンサー ×1  防水ケーブル ×2  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://www.zenshin-tech.com/product/lpms-ig1-can/ "オンラインで注文")  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-IG1-RS485 | LPMS-IG1-RS485センサー ×1  防水ケーブル ×2  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://www.zenshin-tech.com/product/lpms-ig1-rs485/ "オンラインで注文")  [代理店を探す](/ja/distributors-lp-research "代理店") |

![高精度9軸IMU](LpmsIG1-CAN_Box_1024_683_20200301.jpg)

![高精度9軸IMU](LpmsIG1-RS232_Box_1024_683_20200301.jpg)
