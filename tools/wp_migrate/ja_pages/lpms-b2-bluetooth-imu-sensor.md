# LPMS-B2

## LPMS-B2シリーズ: Bluetooth ClassicとBLEに対応した9軸慣性計測装置/AHRS

|  |  |
| --- | --- |
| ![LPMS-B2](H-LPMS-B2.png){width=100%} | ![LPMS-B2 OEM ワイヤレス慣性計測装置（IMU / AHRS）](LpmsB2Oem_1024_683.jpg){width=100%} |
| **LPMS-B2** | **LPMS-B2 OEM** |

### 製品説明

LP-Researchモーションセンサー Bluetoothバージョン2（LPMS-B2）シリーズは、9軸Bluetooth IMU（慣性計測装置）/姿勢方位基準システム（AHRS）です。非常に汎用性が高く、高精度・高速な姿勢計測と相対変位計測を行います。

3種類のMEMSセンサー（3軸ジャイロスコープ、3軸加速度センサー、3軸地磁気センサー）を使用することで、全3軸まわりのドリフトのない高速な姿勢データを実現しています。さらに、温度センサーと気圧センサーにより、高度を正確に測定できます。

LPMS-B2シリーズは、Bluetooth Classic 2.1またはLow Energy 4.1接続でホストシステムと通信します。1台のホストシステムで複数のセンサーを同時に使用できます（Windows/Androidで最大7台）。データ伝送レートは最大400Hzです。

センサーユニットには32ビットのデジタルシグナルプロセッサーが搭載されており、すべての計算をリアルタイムにオンボードで実行できます。当社のセンサーフュージョン手法の詳細については、[IMUcoreの解説](/ja/blog/imucore-sensor-fusion)をご参照ください。

### ダウンロード

[LPMS-B2\_EN](/api/v1/website/assets/260206-LPMS-B2-EN.pdf)、[LPMS-B2\_JP](/api/v1/website/assets/260206-LPMS-B2_JP.pdf)

[クイックスタートガイド](/api/v1/website/assets/20200308LpmsB2QuickStartGuide.pdf)

[3Dメカニカルファイル](/api/v1/website/assets/20180719LpmsB2Series3Dmodel.zip)

[LPMSドキュメントポータル](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1100611840/LPMS+Documentation)

[ソフトウェアダウンロード](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1138294814/LPMS+Data+Acquisition+Software)

### 仕様

| 型番 | LPMS-B2 | LPMS-B2 OEM |
| --- | --- | --- |
| サイズ | 39×39×8mm | 16×31×4mm |
| 重量 | 12g | 2g |
| Bluetooth | 2.1 + EDR / Low Energy (LE) 4.1 | |
| 通信距離 | < 20 m | |
| 姿勢計測範囲 | ロール: ±180°、ピッチ: ±90°、ヨー: ±180° | |
| 分解能 | < 0.01° | |
| 精度 | < 0.5°（静的）、< 2° RMS（動的） | |
| 加速度センサー | 3軸、±2 / ±4 / ±8 / ±16 g、16ビット | |
| ジャイロスコープ | 3軸、±125 / ±245 / ±500 / ±1000 / ±2000 °/s、16ビット | |
| ジャイロスコープ・ノイズ密度 | 0.007 dps/√Hz | |
| 静的姿勢安定性 | 9 °/hour | |
| 地磁気センサー | 3軸、±4 / ±8 / ±12 / ±16 gauss、16ビット | |
| 気圧センサー | 300 – 1100 hPa | |
| データ出力形式 | 生データ / オイラー角 / クォータニオン | |
| データ伝送レート | 最大400Hz | |
| 消費電力 | <132 mW @ 3.3 V | |
| 電源 | バッテリー（6時間以上） | 3.3 ~ 5V |
| 動作温度範囲 | -20 ~ +60 °C | |
| コネクター | Micro USB | Micro USB / SM02B-SURS-TF |
| ソフトウェア | Windows用C++ライブラリ、Android用Javaライブラリ、Windows用LpmsControlソフトウェアおよびOpen Motion Analysis Toolkit（OpenMAT） | |

### ご注文
