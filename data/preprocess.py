import pandas as pd
import numpy as np

file_name = "data/Botnet_Final_Data.csv"

# Raw File
try:
    df = pd.read_csv(file_name)
except FileNotFoundError:
    print(f"ERROR: File not found at {file_name}. Please check the file name and path.")
    exit()

# 1. Clean Column Names
df.columns = df.columns.str.strip()

# 2. Clean Label values and handle NaNs/Infs
df['Label'] = df['Label'].str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# 3. Label Encoding 직접 3으로 지정
# SSH, FTP 침투 공격 및 Bot 라벨을 모두 우리 프로젝트의 봇넷 번호인 3으로 매핑합니다.
df['Label_Encoded'] = df['Label'].apply(lambda x: 3 if x in ['SSH-Patator', 'FTP-Patator', 'Bot'] else 0)

# 4. Core Features
CORE_FEATURES = [
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
    'Subflow Fwd Packets'
]

# 5. 레이블 컬럼 추가
LABEL_COLUMNS = ['Label', 'Label_Encoded']
ALL_COLUMNS = CORE_FEATURES + LABEL_COLUMNS

# 6. 정의된 컬럼만 선택하여 데이터프레임 경량화
try:
    df_lightweight = df[ALL_COLUMNS]
except KeyError as e:
    print(f"\nERROR: 핵심 특징 중 하나({e})가 데이터프레임에 존재하지 않습니다. 컬럼명을 확인해 주세요.")
    exit()

# 7. 파일 저장
output_file = "Botnet_Final_Data.csv"
df_lightweight.to_csv(output_file, index=False)