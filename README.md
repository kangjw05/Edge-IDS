# Edge-IDS

🛡️ Edge-IDS: 엣지 AI 기반 IoT 네트워크 침입 탐지 시스템

📖 프로젝트 개요 (Overview)

Edge-IDS는 IoT 환경의 보안 취약점을 해결하기 위해 개발된 **경량화된 실시간 침입 탐지 시스템(Intrusion Detection System)**입니다.
클라우드가 아닌 엣지 디바이스(Raspberry Pi) 자체에서 AI 모델을 구동하여, 네트워크 지연 없이 실시간으로 공격을 탐지하고 대응합니다.

본 프로젝트는 KIAT 한미 첨단분야 교환학생 프로그램을 위한 연구 프로젝트의 일환으로 개발되었습니다.

🚀 주요 기능 (Key Features)

이 시스템은 네트워크 트래픽을 실시간으로 분석하여 다음 5가지 상태를 정확하게 분류합니다.

🟢 정상 (Benign): 일반적인 네트워크 트래픽

🔍 포트 스캔 (Port Scan): 공격 전 단계의 정찰 행위 탐지

💥 DDoS 공격: 대량의 트래픽을 유발하는 서비스 거부 공격 탐지

🤖 봇넷/브루트포스 (Botnet): Telnet/SSH 무차별 대입 공격 및 봇 감염 시도 탐지

⚠️ ARP 스푸핑 (ARP Spoofing): 내부망 중간자 공격(MITM) 탐지

💡 기술적 차별점

Edge AI: 라즈베리파이 4/5 환경에 최적화된 LightGBM 모델 사용

실시간 패킷 분석: Scapy를 활용한 실시간 트래픽 캡처 및 플로우(Flow) 기반 특징 추출

하이브리드 데이터셋: CICIDS 2017 공개 데이터셋과 자체 생성한 ARP 스푸핑 데이터를 결합하여 학습

🛠️ 시스템 아키텍처 (System Architecture)

graph LR
    A[IoT Network Traffic] --> B(Raspberry Pi / Scapy)
    B --> C{Feature Extraction}
    C --> D[LightGBM AI Model]
    D --> E{Prediction}
    E -- Normal --> F[Pass]
    E -- Attack --> G[Alert / Block]


💻 기술 스택 (Tech Stack)

Hardware: Raspberry Pi 4 Model B (4GB) or Raspberry Pi 5

Language: Python 3.9+

AI/ML: LightGBM, Scikit-learn, Pandas, Joblib

Network: Scapy, Tcpdump

OS: Raspberry Pi OS (64-bit) / Windows (Training)

📂 폴더 구조 (Directory Structure)

Edge-IDS/
├── data/                  # 학습용 데이터셋 (CSV)
│   ├── Botnet_Final_Data.csv
│   ├── DDoS_Final_Data.csv
│   └── PortScan_Final_Data.csv
├── models/                # 학습된 AI 모델 저장소
│   └── multi_attack_ids_model.joblib
├── scripts/               # 소스 코드
│   ├── train_multi_model.py   # 모델 학습 스크립트 (PC용)
│   ├── detect.py              # 실시간 탐지 스크립트 (Pi용)
│   └── arp_data_gen.py        # ARP 데이터 생성기
├── requirements.txt       # 의존성 라이브러리 목록
└── README.md              # 프로젝트 설명서


⚡ 설치 및 사용 방법 (Getting Started)

1. 환경 설정 (Prerequisites)

프로젝트를 클론하고 필요한 라이브러리를 설치합니다. (PC 및 라즈베리파이 공통)

git clone [https://github.com/kangjw05/Edge-IDS.git](https://github.com/kangjw05/Edge-IDS.git)
cd Edge-IDS
pip install -r requirements.txt


2. AI 모델 학습 (PC 권장)

데이터셋을 기반으로 LightGBM 모델을 학습시킵니다.

# 가상환경 활성화 후 실행
python scripts/train_multi_model.py


실행 후 models/multi_attack_ids_model.joblib 파일이 생성됩니다.

3. 실시간 탐지 실행 (Raspberry Pi)

학습된 모델 파일을 라즈베리파이로 옮긴 후 탐지기를 실행합니다.

# 백그라운드 실행 (SSH 연결이 끊겨도 유지됨)
nohup python3 scripts/detect.py &

# 로그 확인
tail -f nohup.out


👨‍💻 팀원 (Team)

Name: 강지원, 이은빈

Role: Project Lead, AI Modeling, Embedded System Implementation

Contact: cindy2005041297@gmail.com / ebin5780@gmail.com

📜 라이선스 (License)

This project is licensed under the MIT License - see the LICENSE file for details.