import pandas as pd
import numpy as np
import os

# 설정
DATA_DIR = "data"
OUTPUT_FILE = os.path.join(DATA_DIR, "Final_Training_Data.csv")

# 파일 경로 정의
FILE_PATHS = {
    'Botnet': os.path.join(DATA_DIR, 'Botnet_Final_Data.csv'),
    'DDoS': os.path.join(DATA_DIR, 'DDoS_Final_Data.csv'),
    'PortScan': os.path.join(DATA_DIR, 'PortScan_Final_Data.csv'),
    'ARP': os.path.join(DATA_DIR, 'ARP_Spoofing_Final_Data.csv')
}

def remap_label(label_val):
    try:
        val = int(float(label_val))
        # 이미 숫자로 1, 2, 3, 4가 되어 있다면 그대로 유지
        if val in [1, 2, 3, 4]: return val
        if val == 5: return 3  # 혹시 5로 되어있을 경우 대비
        return 0
    except:
        label_str = str(label_val).lower()
        if 'portscan' in label_str: return 1
        elif 'ddos' in label_str: return 2
        elif 'bot' in label_str or 'ssh' in label_str or 'ftp' in label_str: return 3
        elif 'arp' in label_str: return 4
        return 0

print("데이터셋 병합을 시작합니다...")
df_list = []

for attack_type, filepath in FILE_PATHS.items():
    if os.path.exists(filepath):
        print(f"Loading {attack_type} data from {filepath}...")
        df = pd.read_csv(filepath)
        
        # [핵심] Label_Encoded 컬럼이 있으면 거기 있는 숫자(3)를 먼저 가져옴
        if 'Label_Encoded' in df.columns:
            print(f"  -> {attack_type}: Label_Encoded 컬럼에서 숫자를 추출합니다.")
            df['Target'] = df['Label_Encoded'].apply(remap_label)
        elif 'Label' in df.columns:
            df['Target'] = df['Label'].apply(remap_label)
        else:
            mapping = {'Botnet':3, 'DDoS':2, 'PortScan':1, 'ARP':4}
            df['Target'] = mapping.get(attack_type, 0)
        
        df_list.append(df)
    else:
        print(f"[Warning] 파일 없음: {filepath}")

# 병합
df_final = pd.concat(df_list, ignore_index=True)

# 불필요한 컬럼 제거 (Label, Label_Encoded 삭제)
cols_to_drop = ['Label', 'Label_Encoded']
df_final.drop(columns=[c for c in cols_to_drop if c in df_final.columns], inplace=True)

# 결측치 처리 및 순서 정리
df_final.fillna(0, inplace=True)
cols = [c for c in df_final.columns if c != 'Target'] + ['Target']
df_final = df_final[cols]

# 저장
df_final.to_csv(OUTPUT_FILE, index=False)

print("\n" + "="*30)
print(f"✅ 최종 데이터셋 저장 완료: {OUTPUT_FILE}")
print("📊 최종 분포 (3번이 있는지 확인!):")
print(df_final['Target'].value_counts().sort_index())
print("="*30)