# LPMS-IG1W

## LPMS-IG1W: Wi-Fiワイヤレス通信対応の9軸IMU（慣性計測装置）/AHRS（姿勢方位基準システム）

![](IG1W-w-Antenna.png)

#### LPMS-IG1W

### 製品説明

LPMS-IG1Wは、姿勢と加速度を非常に高い精度で検出できる、高精度かつコンパクトな9軸IMUセンサーです。PCやスマートフォンなどのホストシステムとWi-Fiで接続し、インターネット接続なしで高速かつ安全なデータ伝送を実現します。

本センサーは、ジャイロスコープ、加速度センサー、地磁気センサーのデータを処理する高性能CPUを搭載し、低ドリフト・高精度のリアルタイム計測結果を提供します。耐久性の高いIP67準拠の防水ケースにより、過酷な環境にも耐えられる設計です。さらに、LPMS-IG1Wはデュアルジャイロスコープを搭載しており、400～2000°/sの広い範囲での計測が可能で、要求の厳しい産業用途に適しています。

LPMS-IG1Wは、高精度かつ低遅延の計測が求められる[IoTアプリケーション](/ja/inertial-measurement-unit-imu-series-2)での使用に最適です。予知保全のための高周波振動検出、無人搬送車（AGV）のナビゲーション、VR/ARシステムのモーショントラッキングなどに応用できます。また、遠隔操作ロボットやロボットアームにも適しており、これらのシナリオで信頼性の高い高精度な性能を発揮します。

センサーのパラメーターとデータ伝送設定は、当社のLPMS ControlソフトウェアまたはOpenMATプラットフォームで自由にカスタマイズできます。Windows、Linux、組み込みシステムとの直接統合のための充実したライブラリサポートもご提供しており、あらゆる構成にLPMS-IG1Wを容易に組み込めます。

当社のセンサーフュージョン技術の詳細については、[IMUcoreの解説](/ja/blog/imucore-sensor-fusion)ページをご参照ください。

### ダウンロード

フライヤー（[LPMS-IG1W\_EN](/api/v1/website/assets/2509-LPMS-IG1W_EN-1.pdf)、[LPMS-IG1W\_JP](/api/v1/website/assets/202604-LPMS-IG1W_JP.pdf)）

[ビデオ](http://vimeo.com/user/9419701/folder/1482077)

[3Dメカニカルファイル](/api/v1/website/assets/20190909LpmsIg13DModel.zip)

[LPMSドキュメントポータル](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1100611840/LPMS+Documentation)

[ソフトウェアダウンロード](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1138294814/LPMS+Data+Acquisition+Software)

### 仕様

| 型番 |  | LPMS-IG1W |  |
| --- | --- | --- | --- |
| インターフェース | Wi-Fi + USB | | |
| 通信プロトコル | LPBUS/CANopen/Sequential CAN | | |
| サイズ | 51 x 45 x 24 mm | | |
| 重量 | 115g | | |
| 姿勢計測範囲 | 全軸360° | | |
| 分解能 | < 0.01° | | |
| 加速度センサー | 3軸、±20/ ±40 / ±80 / ±160 m/s2、16ビット | | |
| ジャイロスコープ（2種搭載） | ジャイロ#1: 3軸、±400 dps、24ビット、ジャイロ#2: 3軸、±1000 / ±2000 dps、16ビット | | |
| ジャイロスコープ・ノイズ密度 | #1: 0.002 dps/√Hz、#2: 0.004 dps/√Hz | | |
| 地磁気センサー | 3軸、±4 / ±8 / ±12 / ±16 gauss、16ビット | | |
| 精度 | < 0.3°（静的）、< 1° RMS（動的） | | |
| 静的姿勢安定性 | #1: 4 °/hour、#2: 6 °/hour | | |
| データ出力形式 | 生データ / オイラー角 / クォータニオン | | |
| データ出力レート | 5 ~ 500 Hz | | |
| 消費電力 | 0.85W（0.070A@12 V） | | |
| 電源 | 5 V ~ 12 V DC | | |
| コネクター | M12 8ピン（SACC-DSI-MS-8CON-PG 9/0,5 SCO相当）、SMAコネクター（アンテナ用） | | |
| ハウジング | アルミニウム、IP67準拠 | | |
| 動作温度範囲 | -20 ~ +80 °C（ご要望により -40 ~ +80 °C） | | |
| Wi-Fi情報 | 最大伝送距離 10~30m（※1）、Wi-Fi周波数帯 2.4GHz、通信プロトコル: TCP/IPまたはMQTT、Wi-Fi出力周波数: MQTT 5~200Hz、ソケット 5~500Hz | | |
| ソフトウェア | Windows用C++ライブラリ、Android用Javaライブラリ、LPMS Control（データ分析ソフトウェア）、Windows用Open Motion Analysis Toolkit（OpenMAT） | | |

※1 通信距離は使用環境によって変わる場合があります。  
※ 性能パラメーターは+25°Cで測定しています。その他の温度では基準値が異なる場合があります。詳細な仕様については製品マニュアルをご参照ください。

### ご注文

| 製品 | パッケージ内容 | 価格 |
| --- | --- | --- |
| LPMS-IG1W | LPMS-IG1Wセンサー ×1  アンテナ ×1  防水ケーブル ×2  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-ig1w/)  [代理店を探す](/ja/distributors-lp-research "代理店") |

![](lpms-ig1w_package_small.png)
