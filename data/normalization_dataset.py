import pandas as pd
import numpy as np

# ==========================================
# 설정
# ==========================================
INPUT_FILE = "data/Final_Training_Data.csv"
OUTPUT_FILE = "data/Final_Normalized_Training_Data.csv"
TARGET_DURATION = 2000000  # 2초 (마이크로초)

def finalize_normalization():
    print(f"[*] {INPUT_FILE} 보정 및 데이터 정규화 시작...")
    
    try:
        df = pd.read_csv(INPUT_FILE)
        
        # 1. 결측치 및 무한대 처리
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        # 2. 모든 데이터를 '2초 윈도우'로 강제 고정
        # 원본 Duration이 얼마든, AI가 볼 데이터는 '2초간의 기록'이어야 함
        actual_durations = df['Flow Duration'].replace(0, 1)
        
        # 3. 개수(Count) 기반 컬럼들 업데이트
        # PPS(밀도)는 유지하되, 2초 동안 발생했을 패킷 '개수'로 환산
        # 원래 PPS가 17,000이었다면 2초 동안은 34,000개가 온 것으로 계산됨
        count_features = [
            'Total Fwd Packets', 
            'Total Backward Packets', 
            'Subflow Fwd Packets',
            'SYN Flag Count', 
            'ACK Flag Count'
        ]
        
        # 보정 전 PPS 저장 (재계산용)
        # 만약 원본 데이터에 PPS 컬럼이 없다면 직접 계산해서 써야 함
        if 'Flow Packets/s' not in df.columns:
            df['Flow Packets/s'] = df['Total Fwd Packets'] / (actual_durations / 1000000)

        # 모든 Duration을 2초로 고정
        df['Flow Duration'] = TARGET_DURATION

        # 4. 핵심 지표 재계산 (AI가 실제 환경과 똑같이 느끼게 함)
        # 정상 데이터의 PPS가 17,000으로 너무 높으면 공격 탐지가 안 됨
        # 그래서 정상(Target 0) 데이터의 PPS를 현실적인 수치(예: 10~50)로 낮춰주는 작업이 필요함
        
        print("[*] 정상 데이터 수치 현실화 및 공격 지표 보정 중...")
        
        # 정상(0) 데이터의 패킷 수를 2초 동안 20~60개 정도로 랜덤하게 조정
        # (현실적인 IoT 기기의 평상시 트래픽 수준)
        is_benign = (df['Target'] == 0)
        df.loc[is_benign, 'Total Fwd Packets'] = np.random.randint(10, 40, size=is_benign.sum())
        df.loc[is_benign, 'Flow Packets/s'] = df.loc[is_benign, 'Total Fwd Packets'] / 2.0
        df.loc[is_benign, 'Flow IAT Mean'] = (2000000 / df.loc[is_benign, 'Total Fwd Packets'])
        
        # 공격 데이터는 2초 기준으로 개수 재산정
        is_attack = (df['Target'] != 0)
        # PPS를 유지하면서 2초 동안의 패킷 수로 바꿈
        df.loc[is_attack, 'Total Fwd Packets'] = (df.loc[is_attack, 'Flow Packets/s'] * 2).round().astype(int)
        # IAT Mean도 2초 기준 PPS에 맞춰 재계산
        df.loc[is_attack, 'Flow IAT Mean'] = 2000000 / df.loc[is_attack, 'Total Fwd Packets'].replace(0, 1)

        # 5. 저장
        df.to_csv(OUTPUT_FILE, index=False)
        print(f"✅ 보정 완료! {OUTPUT_FILE} 저장됨.")
        
        # 확인 출력
        print("\n[검증] 라벨별 PPS 평균값 (이게 현실적이어야 탐지가 됨):")
        print(df.groupby('Target')['Flow Packets/s'].mean())

    except Exception as e:
        print(f"❌ 오류 발생: {e}")

if __name__ == "__main__":
    finalize_normalization()