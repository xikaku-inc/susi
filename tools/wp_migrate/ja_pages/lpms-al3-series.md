# LPMS-AL3

## LPMS-AL3シリーズ: CAN/RS232/TTL/USB対応・IP67準拠筐体の9軸慣性計測装置（IMU）/AHRS

|  |  |
| --- | --- |
| ![LPMS-CANAL3](LpmsCANAL3_1024_683_20210803.jpg){width=100%} | ![LPMS-RS232AL3](LpmsRS232AL3_1024_683_20210803.jpg){width=100%} |
| **LPMS-CANAL3** | **LPMS-RS232AL3** |


|  |  |
| --- | --- |
| ![LPMS-TTLAL3](LPMS-TTLAL3_1024_683_20210803.jpg){width=100%} |  |
| **LPMS-TTLAL3** |  |


### 製品説明

LP-ResearchモーションセンサーLPMS-AL3シリーズは、CAN、RS232、TTL、USBなど多彩な接続方式に対応した9軸防水慣性計測装置（IMU）/AHRSです。防水性能IP67準拠の筐体を採用しています。この9軸防水IMUシリーズのセンサーユニットは非常に汎用性が高く、高精度・高速な姿勢計測を行います。3種類のMEMSセンサー（3軸ジャイロスコープ、3軸加速度センサー、3軸地磁気センサー）の組み合わせにより、全3軸まわりの低ドリフト・低遅延の姿勢データを実現しています。

各センサーユニットには32ビットのデジタルシグナルプロセッサーが搭載されており、すべての計算をリアルタイムにオンボードで実行できます。当社のセンサーフュージョン手法の詳細については、[IMUcoreの解説](/ja/blog/imucore-sensor-fusion)をご参照ください。

センサーのCANバスインターフェースは、より大規模なCANインフラへのセンサー接続を可能にします。CANタイプのセンサーは、CANopen規格のサブセットと、カスタマイズ可能なシーケンシャルCANメッセージ形式をサポートします。CANバス経由で送信する計測データの内容は、LpmsControlデータ収集ソフトウェアで自由に設定できます。センサーの転送レート設定に応じて、最大500Hzのデータレートを実現します。

センサーのRS232/TTL通信には、当社独自のLP-BUSプロトコルまたはプレーンASCII出力形式を使用できます。

### ダウンロード

フライヤー（[LPMS-CANAL3](/api/v1/website/assets/20250901_LPMS-CANAL3_EN.pdf)、[LPMS-RS232AL3](/api/v1/website/assets/202509018_LPMS-RS232AL3_EN.pdf)、[LPMS-TTLAL3](/api/v1/website/assets/20250918_LPMS-TTLAL3_EN.pdf)）

（[LPMS-CANAL3\_JP](/api/v1/website/assets/20250901_LPMS-CANAL3_JP.pdf)、[LPMS-RS232AL3\_JP](/api/v1/website/assets/20250918_LPMS-RS232AL3_JP.pdf)、[LPMS-TTLAL3\_JP](/api/v1/website/assets/20250918_LPMS-TTLAL3_JP.pdf)）

[3Dメカニカルファイル](/api/v1/website/assets/AL3series-3D-files.zip)

[LPMSドキュメントポータル](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1941635073/LPMS3+Series+Documentation)

[ソフトウェアダウンロード](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1138294814/LPMS+Data+Acquisition+Software)

### 仕様

|  |  |  |  |
| --- | --- | --- | --- |
| 型番 | **LPMS-CANAL3** | **LPMS-RS232AL3** | **LPMS-TTLAL3** |
| 通信インターフェース | CANバス / USB | RS232 | TTL（UART） |
| 最大ボーレート | 1Mbps | 921600bps | 921600bps |
| 通信プロトコル | CANOpen / SequentialCAN | LPBUS/ASCII | LPBUS/ASCII |
| 消費電力 | <135mW@5V | <110mW@5V | <90mW@5V |
| サイズ | 50x42x25mm（最新バージョン） | | |
| 重量 | 106.8（±4）g | | |
| オイラー角範囲 | ロール: ±180°、ピッチ: ±90°、ヨー: ±180° | | |
| 分解能 | 0.01° | | |
| 精度 | < 0.5°（静的）、< 2° RMS（動的） | | |
| 最大瞬間衝撃（0.1ms） | 10,000g | | |
| 出力データ形式 | 生データ/オイラー角/クォータニオン/線形加速度/気圧/温度 | | |
| 内部サンプリングレート | 500Hz | | |
| 最大データ更新レート | 500Hz | | |
| 加速度センサー範囲 | 3軸、±2/±4/±8/±16g、16ビット | | |
| ジャイロスコープ範囲 | 3軸、±125/±250/±500/±1000/±2000/±4000°/s、16ビット | | |
| ジャイロスコープ・ノイズ密度 | 0.005dps/√Hz | | |
| 地磁気センサー範囲 | 3軸、±2/±8gauss、16ビット | | |
| 動作温度範囲 | -20~80°C | | |
| 電源 | 5V ~ 18V DC | | |
| コネクター | M12 8ピン | | |
| 防水性能 | アルミニウム合金、IP67 | | |

### ご注文

| 製品 | パッケージ内容 | 価格 |
| --- | --- | --- |
| LPMS-CANAL3 | LPMS-CANAL3センサー ×1  ケーブル（M12コネクター～オープンワイヤー） ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-canal3/)  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-RS232AL3 | LPMS-RS232AL3センサー ×1  ケーブル（M12コネクター～オープンワイヤー） ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-rs232al3/)  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-TTLAL3 | LPMS-TTLAL3センサー ×1  ケーブル（M12コネクター～オープンワイヤー） ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/product/lpms-ttlal3-compact-9-axis-imu-ahrs-with-ttl-serial-interface/)  [代理店を探す](/ja/distributors-lp-research "代理店") |

![](LpmsCANAL3_Box_1024_683_20210803.jpg)

![](LpmsRS232AL3_Box_1024_683_20210803.jpg)

![](LpmsTTLAL3_Box_1024_683_20210803.jpg)
