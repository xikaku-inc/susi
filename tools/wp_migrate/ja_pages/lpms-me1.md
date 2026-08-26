# LPMS-ME1

## LPMS-ME1: UART、I2C、SPI対応の超小型9軸慣性計測装置（IMU）/AHRS

注: 本製品はレガシー製品です。新規のアプリケーションについては、[LPMS-BEをご検討いただくか、お問い合わせ](/ja/contact-lp-research)ください。

![](20161014LpmsME1Oem_600_400.jpg)

### 製品説明

LPMS-ME1は、複数の通信インターフェースを備えた高性能・超小型の慣性計測装置（IMU）です。UART、I2C、SPIを1つのユニットに統合したLPMS-ME1は、サイズとコストが重視される用途における機械・人体のモーション計測のどちらにも最適です。LPMS-ME1は当社最小のセンサーソリューションで、12×12mmの多層PCBのみで構成され、表面実装部品としてお客様の設計に組み込めます。

本ユニットには32ビットのデジタルシグナルプロセッサーが搭載されており、すべての計算をリアルタイムにオンボードで実行できます。当社のセンサーフュージョン手法の詳細については、[IMUcoreの解説](/ja/blog/imucore-sensor-fusion)をご参照ください。

LPMS-ME1に基づくハードウェア・ソフトウェア設計を容易にするため、USBでPCに接続できる開発キットをご用意しています。当社のLPMS-Controlアプリケーションですべてのセンサーパラメーターを設定でき、ボードには関連するセンサーピンに簡単にアクセスできるピンヘッダーも備わっています。

### ダウンロード

[データシート](/api/v1/website/assets/20190902LpmsME1FlyerEng-2.pdf)

[LPMSドキュメントポータル](https://lp-research.atlassian.net/wiki/spaces/LKB/pages/1100611840/LPMS+Documentation)

[ソフトウェアダウンロード](https://lp-research.atlassian.net/wiki/spaces/LKB/overview)

### 仕様

| 通信インターフェース | UART、I2C、SPI |
| --- | --- |
| 通信プロトコル | LpBUS（UARTインターフェース） |
| サイズ | 12 x 12 x 2.6 mm |
| 重量 | 0.3g |
| 姿勢計測範囲 | ロール: ±180°、ピッチ: ±90°、ヨー: ±180° |
| 分解能 | 0.01° |
| 精度 | < 0.5°（静的）、< 2° RMS（動的） |
| 加速度センサー | 3軸、±20 / ±40 / ±80 / ±160 m/s2、16ビット |
| ジャイロスコープ | 3軸、±125 / ±245 / ±500 / ±1000 / ±2000 °/s、16ビット |
| ジャイロスコープ・ノイズ密度 | 0.007 dps/√Hz |
| 静的姿勢安定性 | 9 °/hour |
| 地磁気センサー | 3軸、±4 / ±8 / ±12 / ±16 gauss、16ビット |
| データ出力形式 | 生データ / オイラー角 / クォータニオン |
| データ伝送レート | 最大400 Hz |
| 消費電力（100Hz、UART） | <20mA @ 3.3V |
| 電源 | 3.3 ~ 5.5V DC |
| 動作温度範囲 | – 40 ~ +80 °C |
| ソフトウェア | Windows用C++ライブラリ、Windows用LpmsControlソフトウェアおよびOpen Motion Analysis Toolkit（OpenMAT） |

### ご注文

| 製品 | パッケージ内容 | 価格 |
| --- | --- | --- |
| LPMS-ME1 | LPMS-ME1センサー ×1  ユーザーガイドカード ×1  保証サービス（1年） ×1 | [オンラインで注文](https://www.zenshin-tech.com "オンラインで注文")  [代理店を探す](/ja/distributors-lp-research "代理店") |
| LPMS-ME1 DK | LPMS-ME1センサー ×1  開発キットベースボード ×1  保証・サポート（1年） ×1 | [オンラインで注文](https://zenshin-tech.com/ "オンラインで注文")  [代理店を探す](/ja/distributors-lp-research "代理店") |

![](LPMS-ME1-DK-V1.2-20181023.png)
