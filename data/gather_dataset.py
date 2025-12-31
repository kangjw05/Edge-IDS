# import pandas as pd
# import numpy as np
# import os

# # 설정
# DATA_DIR = "data"
# OUTPUT_FILE = os.path.join(DATA_DIR, "Temp_Training_Data.csv")

# # 파일 경로 정의 (실제 파일명이랑 일치해야 함)
# FILE_PATHS = {
#     'Botnet': os.path.join(DATA_DIR, 'Botnet_Final_Data.csv'),
#     'DDoS': os.path.join(DATA_DIR, 'DDoS_Final_Data.csv'),
#     'PortScan': os.path.join(DATA_DIR, 'PortScan_Final_Data.csv'),
#     'ARP': os.path.join(DATA_DIR, 'ARP_Spoofing_Final_Data.csv')
# }

# # 라벨 매핑 함수 (핵심!)
# # 0:정상, 1:PortScan, 2:DDoS, 3:Botnet, 4:ARP
# def remap_label(label_str):
#     label_str = str(label_str).lower()
    
#     if 'benign' in label_str:
#         return 0  # 정상
#     elif 'portscan' in label_str:
#         return 1  # 포트 스캔
#     elif 'ddos' in label_str:
#         return 2  # DDoS
#     elif 'bot' in label_str:
#         return 3  # Botnet (Brute Force 포함)
#     elif 'arp' in label_str:
#         return 4  # ARP Spoofing
#     else:
#         return 0  # 예외 케이스는 정상 처리

# # 데이터 병합 시작
# print("데이터셋 병합을 시작")

# df_list = []

# for attack_type, filepath in FILE_PATHS.items():
#     if os.path.exists(filepath):
#         print(f"Loading {attack_type} data from {filepath}...")
#         try:
#             df = pd.read_csv(filepath)
#             df_list.append(df)
#         except Exception as e:
#             print(f"Error loading {filepath}: {e}")
#     else:
#         print(f"[Warning] 파일이 없습니다: {filepath} (이 공격 유형은 제외됩니다)")

# if not df_list:
#     print("병합할 데이터가 없음")
#     exit()

# # 하나로 합치기
# df_final = pd.concat(df_list, ignore_index=True)
# print(f"전체 데이터 개수: {len(df_final)}")

# # 전처리 및 저장

# # 1. 라벨 인코딩 (문자 -> 숫자 0~4)
# print("라벨 인코딩 중...")
# df_final['Target'] = df_final['Label'].apply(remap_label)

# # 2. 불필요한 컬럼 제거
# # 학습에 방해되는 기존 Label, Label_Encoded 컬럼 삭제
# cols_to_drop = ['Label', 'Label_Encoded']
# # 실제로 존재하는 컬럼만 삭제
# cols_to_drop = [c for c in cols_to_drop if c in df_final.columns]
# df_final.drop(columns=cols_to_drop, inplace=True)

# # 3. 결측치(NaN) 처리
# df_final.fillna(0, inplace=True)

# # 4. 컬럼 순서 정리 (Target을 맨 뒤로)
# # 현재 컬럼 목록 가져오기
# cols = [c for c in df_final.columns if c != 'Target']
# cols.append('Target') # Target을 맨 끝에 추가
# df_final = df_final[cols]

# # 5. 저장
# df_final.to_csv(OUTPUT_FILE, index=False)

# print("="*30)
# print(f"최종 데이터셋 저장 완료: {OUTPUT_FILE}")
# print("클래스별 데이터 분포:")
# print(df_final['Target'].value_counts().sort_index())
# print("="*30)
# print("(0:Normal, 1:PortScan, 2:DDoS, 3:Botnet, 4:ARP)")

import pandas as pd
import os

# 파일 경로 설정
TEMP_FILE = "data/Temp_Training_Data.csv"
ARP_FILE = "data/ARP_Spoofing_Final_Data.csv"
FINAL_COMBINED = "data/Final_Training_Data.csv"

# 1. 기존 3종 합본 로드
df_temp = pd.read_csv(TEMP_FILE)

# 2. 방금 만든 ARP 데이터 로드
df_arp = pd.read_csv(ARP_FILE)

# 3. ARP 라벨 인코딩 (혹시 숫자가 아니면 4로 변경)
# pcap_to_csv에서 'ARP'라는 문자열로 넣었을 경우를 대비
if df_arp['Label'].dtype == 'object':
    df_arp['Target'] = 4
    df_arp.drop(columns=['Label'], inplace=True)

# 4. 두 데이터 합치기
df_final = pd.concat([df_temp, df_arp], ignore_index=True)

# 5. 저장
df_final.to_csv(FINAL_COMBINED, index=False)

print(f"합체 완료! 최종 파일: {FINAL_COMBINED}")
print("클래스 분포:\n", df_final['Target'].value_counts().sort_index())