# LPMS-U3

## LPMS-U3シリーズ: USB、RS232、TTL、CANに対応した9軸慣性計測装置/AHRS

|  |  |
| --- | --- |
| ![LPMS-CU3](LpmsCU3_1024_683-20211224.jpg){width=100%} | ![LPMS-URS3](LpmsURS3_1024_683-20211224.jpg){width=100%} |
| **LPMS-CU3** | **LPMS-URS3** |


|  |  |
| --- | --- |
| ![LPMS-UTTL3](LpmsUTTL3_1024_683-20211224.jpg){width=100%} |  |
| **LPMS-UTTL3** |  |


### 製品説明

LPMS-U3センサーシリーズは、USB、RS232、TTL、CANバスといった多彩な通信インターフェースを備えた、超小型の9軸IMU（慣性計測装置）/姿勢方位基準システム（AHRS）のシリーズです。この9軸USB・CANバスIMUセンサーは非常に汎用性が高く、高精度・高速な姿勢計測と相対変位計測を行います。

3種類のMEMSセンサー（3軸ジャイロスコープ、3軸加速度センサー、3軸地磁気センサー）を使用することで、全3軸まわりの低ドリフトかつ高速な姿勢データを実現しています。さらに、温度と気圧により高度を正確に測定できます。LPMS-U3シリーズは、USB、RS232、TTLまたはCANバス接続でホストシステムと通信できます。センサーの設定に応じて、最大500Hzのデータ転送レートを実現します。

この9軸USB・CANバスIMUセンサーは、サイズとコストが重視される用途における機械・人体のモーション計測のどちらにも適しています。全センサーに32ビットのデジタルシグナルプロセッサーが搭載されており、すべての計算をリアルタイムにオンボードで実行できます。当社のセンサーフュージョン手法の詳細については、[IMUcoreの解説](/ja/blog/imucore-sensor-fusion)をご参照ください。

特にLPMS-CU3センサーのCANバスインターフェースは、より大規模なCANバスインフラへのセンサー接続を可能にします。最小構成のCANopen実装と、カスタマイズ可能なシーケンシャルCANメッセージ形式をサポートしています。

すべてのセンサーのパラメーター設定は、当社のLPMS-Control2ソフトウェアで自由に構成できます。

### ダウンロード

フライヤー（[LPMS-CU3\_EN](/api/v1/website/assets/20251007_LPMS-CU3_EN.pdf)、[LPMS-URS3\_EN](/api/v1/website/assets/20251009_LPMS-URS3_EN.pdf)、[LPMS-UTTL3\_EN](/api/v1/website/assets/20251009_LPMS-UTTL3-EN.pdf)）  
（[LPMS-CU3\_JP](/api/v1/website/assets/20250919_LPMS-CU3-JP.pdf)、[LPMS-URS3\_JP](/api/v1/website/assets/20251009_LPMS-URS3_JP.pdf)、[LPMS-UTTL3\_JP](/api/v1/website/assets/20251009_LPMS-UTTL3-JP.pdf)）

[3Dメカニカルファイル](/api/v1/website/assets/LPMS-U2-3series_3D-file.zip)

[LPMSドキュメントポータル](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1100611840/LPMS+Documentation)

[ソフトウェアダウンロード](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1138294814/LPMS+Data+Acquisition+Software)

### 仕様

| 型番 | LPMS-CU3 | LPMS-URS3 | LPMS-UTTL3 |
| --- | --- | --- | --- |
| 通信インターフェース | CANバス、USB 2.0 | RS232、USB 2.0 | TTL、USB 2.0 |
| 通信プロトコル | LPCAN/ CANOpen/ SequentialCAN | LpBUS/ASCII | LpBUS/ASCII |
| サイズ | 34 x 34.5 x 15.7 mm | | |
| 重量 | 17.6g | | |
| 姿勢計測範囲 | ロール: ±180°、ピッチ: ±90°、ヨー: ±180° | | |
| 分解能 | 0.01° | | |
| 精度 | < 0.5°（静的）、< 2° RMS（動的） | | |
| 加速度センサー | 3軸、±20 / ±40 / ±80 / ±160 m/s2、16ビット | | |
| ジャイロスコープ | 3軸、±125 / ±250 / ±500 / ±1000 / ±2000 / ±4000°/s、16ビット | | |
| ジャイロスコープ・ノイズ密度 | 0.005 dps/√Hz | | |
| 地磁気センサー | 3軸、±2 / ±8 gauss、16ビット | | |
| 気圧センサー | 300 – 1100 hPa | | |
| データ出力形式 | 生データ / オイラー角 / クォータニオン | | |
| データ伝送レート | 最大500 Hz | | |
| 消費電力 | 0.021A@12V | 0.021A@12V | 0.017A@12V |
| 電源 | 5 ~ 18 V DC | | |
| コネクター | DB9メス / Micro USB-B（USB） | | |
| ケース材質 | ABS樹脂シェル | | |
| 動作温度範囲 | – 20 ~ +80 °C（ご要望により – 40 ~ +80 °C） | | |
| ソフトウェア | Windows用C++ライブラリ、LpmsControl2ソフトウェア | | |

### ご注文

| 製品 | パッケージ内容 | 価格 |
| --- | --- | --- |
| LPMS-CU3 | LPMS-CU3センサー ×1  Micro USBケーブル ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-cu3-9-axis-inertial-measurement-unit-imu-with-can-and-usb-connectivity/)  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-URS3 | LPMS-URS3センサー ×1  Micro USBケーブル ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-urs3-9-axis-inertial-measurement-unit-imu-with-usb-and-rs232-connectivity/)  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-UTTL3 | LPMS-UTTL3センサー ×1  Micro USBケーブル ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-uttl3-9-axis-imu-ahrs-with-ttl-uart-interface/)  [代理店を探す](/ja/distributors-lp-research "代理店") |

![](LpmsCU3_Box_1024_683-20211224.jpg)

![](LpmsURS3_Box_1024_683-20211224.jpg)

![](LpmsUTTL3_Box_1024_683-20211224.jpg)
