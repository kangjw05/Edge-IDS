import pandas as pd
import numpy as np
import os

# 설정: 저장 경로 및 데이터 개수
DATA_DIR = "data"  # 데이터 저장 폴더
OUTPUT_FILE = os.path.join(DATA_DIR, "ARP_Spoofing_Final_Data.csv")
NUM_SAMPLES = 5000  # 생성할 데이터 개수

# 폴더가 없으면 생성
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# 1. 컬럼 정의
# 업로드된 기존 CSV 파일(Botnet, DDoS 등)과 동일한 컬럼 순서와 이름.

columns = [
    'Flow Bytes/s', 
    'Flow Packets/s', 
    'Destination Port', 
    'Flow Duration',
    'Total Fwd Packets', 
    'Total Backward Packets', 
    'Flow IAT Mean',
    'Fwd Packet Length Mean', 
    'Max Packet Length', 
    'SYN Flag Count',
    'ACK Flag Count', 
    'Init_Win_bytes_forward', 
    'Active Mean',
    'Min Packet Length', 
    'Subflow Fwd Packets', 
    'Label'
    # 'Label_Encoded'는 학습 단계에서 다시 매핑.
]

# 빈 데이터프레임 생성
df_arp = pd.DataFrame(columns=columns)

print(f"Generating {NUM_SAMPLES} synthetic ARP Spoofing samples...")

# 2. ARP 스푸핑 특징(Feature) 시뮬레이션
# ARP 공격의 물리적/네트워크적 특성을 숫자로 반영.

# A. [기본 정보]
# ARP는 2계층 프로토콜이므로 포트 번호 개념이 없음. (0으로 설정)
df_arp['Destination Port'] = 0 

# B. [패킷 길이]
# ARP 패킷은 크기가 작고 고정적 (일반적으로 28~60 바이트 내외).
# => 평균, 최대, 최소 길이가 모두 작게 설정
df_arp['Fwd Packet Length Mean'] = np.random.uniform(28, 60, size=NUM_SAMPLES)
df_arp['Max Packet Length'] = 60
df_arp['Min Packet Length'] = 28

# C. [트래픽 특성]
# 공격자는 피해자의 ARP 테이블을 변조하기 위해 계속 패킷을 보냄
# -> Flow IAT Mean(패킷 간격)이 매우 짧음
# -> Flow Packets/s(초당 패킷 수)가 매우 높음
df_arp['Flow IAT Mean'] = np.random.uniform(1, 500, size=NUM_SAMPLES) # 마이크로초 단위 (매우 짧음)
df_arp['Flow Packets/s'] = np.random.uniform(1000, 20000, size=NUM_SAMPLES) # 초당 수천 개
df_arp['Flow Bytes/s'] = df_arp['Flow Packets/s'] * df_arp['Fwd Packet Length Mean'] # 바이트율 계산

# D. [패킷 수 및 방향]
# 공격자가 일방적으로 보내는 패킷(Fwd)이 많고, 응답(Backward)은 거의 0
df_arp['Total Fwd Packets'] = np.random.randint(20, 200, size=NUM_SAMPLES)
df_arp['Total Backward Packets'] = 0
df_arp['Subflow Fwd Packets'] = df_arp['Total Fwd Packets'] # Subflow도 동일하게 설정

# E. [시간]
# 공격 지속 시간은 다양하게 설정 (짧은 공격 ~ 긴 공격)
df_arp['Flow Duration'] = np.random.randint(10000, 10000000, size=NUM_SAMPLES)

# F. [TCP 플래그 및 윈도우 사이즈]
# ARP는 TCP가 아니므로 SYN, ACK 플래그, 윈도우 사이즈 개념이 없음.
df_arp['SYN Flag Count'] = 0
df_arp['ACK Flag Count'] = 0
df_arp['Init_Win_bytes_forward'] = -1  # 없는 경우 보통 -1 또는 0
df_arp['Active Mean'] = 0

# 3. 라벨링 및 저장
df_arp['Label'] = 'ARP_Spoofing'

# 최종 CSV 저장
df_arp.to_csv(OUTPUT_FILE, index=False)

print(f"Done! File saved at: {OUTPUT_FILE}")
print(f"Columns generated: {list(df_arp.columns)}")