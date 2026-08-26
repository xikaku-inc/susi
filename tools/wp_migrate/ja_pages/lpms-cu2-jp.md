# LPMS-U2シリーズ: USB、RS232、TTL、CANに対応した9軸慣性計測装置/AHRS

注: 本製品はレガシー製品です。新規のアプリケーションについては、[LPMS-U3](/ja/lpms-u3-9-axis-imu)をご参照ください。

![LPMS-CU2 CANバス慣性計測装置（IMU / AHRS）](LpmsCU2_600_400_2.jpg)

## LPMS-CU2

![LPMS-URS2 RS232慣性計測装置（IMU / AHRS）](LpmsURS2_600_400_2.jpg)

## LPMS-URS2

![LPMS-TTL2 UART慣性計測装置（IMU / AHRS）](LpmsUTTL2_600_400_2.jpg)

## LPMS-UTTL2

## 製品説明

LPMS-U2センサーシリーズは、USB、RS232、TTL、CANバスといった多彩な通信インターフェースを備えた、超小型の9軸IMU（慣性計測装置）/姿勢方位基準システム（AHRS）のシリーズです。本シリーズのユニットは非常に汎用性が高く、高精度・高速な姿勢計測と相対変位計測を行います。

3種類のMEMSセンサー（3軸ジャイロスコープ、3軸加速度センサー、3軸地磁気センサー）を使用することで、全3軸まわりの低ドリフトかつ高速な姿勢データを実現しています。さらに、温度と気圧により高度を正確に測定できます。LPMS-U2シリーズは、USB、RS232、TTLまたはCANバス接続でホストシステムと通信できます。センサーの設定に応じて、最大400Hzのデータ転送レートを実現します。

本シリーズは、サイズとコストが重視される用途における機械・人体のモーション計測のどちらにも適しています。全センサーに32ビットのデジタルシグナルプロセッサーが搭載されており、すべての計算をリアルタイムにオンボードで実行できます。当社のセンサーフュージョン手法の詳細については、[IMUcoreの解説](/ja/blog/imucore-sensor-fusion)をご参照ください。

特にLPMS-CU2センサーのCANバスインターフェースは、より大規模なCANバスインフラへのセンサー接続を可能にします。最小構成のCANopen実装と、カスタマイズ可能なシーケンシャルCANメッセージ形式をサポートしています。

すべてのセンサーのパラメーター設定は、当社のLPMS-Controlソフトウェアで自由に構成できます。

## ダウンロード

フライヤー（[LPMS-CU2](/api/v1/website/assets/20180509LpmsCU2FlyerEng.pdf)、[LPMS-URS2](/api/v1/website/assets/20180509LpmsURS2FlyerEng.pdf)、[LPMS-UTTL2](/api/v1/website/assets/20180509LpmsUTTL2FlyerEng.pdf)）

[LPMSドキュメントポータル](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1100611840/LPMS+Documentation)

[ビデオ](http://vimeo.com/user/9419701/folder/1493848)

[3Dメカニカルモデル](/api/v1/website/assets/20180914LpmsU2-3DModel.zip)

[ソフトウェアダウンロード](https://lp-research.atlassian.net/wiki/spaces/LKB/overview)

## 仕様

|  |  |  |  |
| --- | --- | --- | --- |
| 型番 | **LPMS-CU2** | **LPMS-URS2** | **LPMS-UTTL2** |
| 通信インターフェース | CANバス、USB 2.0 | RS232、USB 2.0 | TTL、USB 2.0 |
| 通信プロトコル | LpCAN / CANOpen | LpBUS | LpBUS |
| サイズ | 34 x 34.5 x 15.7 mm | | |
| 重量 | 17.6g | | |
| 姿勢計測範囲 | ロール: ±180°、ピッチ: ±90°、ヨー: ±180° | | |
| 分解能 | < 0.01° | | |
| 精度 | < 0.5°（静的）、< 2° RMS（動的） | | |
| 加速度センサー | 3軸、±20 / ±40 / ±80 / ±160 m/s2、16ビット | | |
| ジャイロスコープ | 3軸、±125 / ±245 / ±500 / ±1000 / ±2000 °/s、16ビット | | |
| ジャイロスコープ・ノイズ密度 | 0.007 dps/√Hz | | |
| 静的姿勢安定性 | 9 °/hour | | |
| 地磁気センサー | 3軸、±4 / ±8 / ±12 / ±16 gauss、16ビット | | |
| 気圧センサー | 300 – 1100 hPa | | |
| データ出力形式 | 生データ / オイラー角 / クォータニオン | | |
| データ伝送レート | 最大400 Hz | | |
| 消費電力 | < 165 mW @ 3.3 V | | |
| 電源 | 5 ~ 18 V DC / 5 V DC（USB） | | |
| コネクター | DB9メス / Micro USB-B（USB） | | |
| ケース材質 | ABS樹脂シェル | | |
| 動作温度範囲 | – 40 ~ +80 °C | | |
| ソフトウェア | Windows用C++ライブラリ、Windows用LpmsControlソフトウェアおよびOpen Motion Analysis Toolkit（OpenMAT） | | |

## ご注文

| 製品 | パッケージ内容 | 価格 |
| --- | --- | --- |
| LPMS-CU2 | LPMS-CU2センサー ×1  Micro USBケーブル ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://www.zenshin-tech.com "オンラインで注文")  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-URS2 | LPMS-URS2センサー ×1  Micro USBケーブル ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://www.zenshin-tech.com "オンラインで注文")  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-UTTL2 | LPMS-UTTL2センサー ×1  Micro USBケーブル ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://www.zenshin-tech.com "オンラインで注文")  [代理店を探す](/ja/distributors-lp-research "代理店") |

![](LpmsCU2_Box_1024_683.jpg)

![](LpmsURS2_Box_1024_683.jpg)

![](LpmsUTTL2_Box_1024_683.jpg)
