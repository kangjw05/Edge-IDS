import pandas as pd
import numpy as np

# ==========================================
# 설정
# ==========================================
INPUT_CSV = 'data/Final_Training_Data.csv'
OUTPUT_CSV = 'data/Rescaled_Training_Data.csv'
TARGET_WINDOW_MS = 2000  # 탐지기 윈도우 크기 (2초)
TARGET_WINDOW_US = TARGET_WINDOW_MS * 1000 # 마이크로초 단위

def rescale_to_window(df):
    print(f"[Process] 데이터 변환 시작 (기준: {TARGET_WINDOW_MS/1000}초)...")
    
    # 원본 데이터 복사
    rescaled_df = df.copy()

    # 1. 스케일링 팩터 계산
    # Flow Duration이 0인 경우 방지
    duration_us = rescaled_df['Flow Duration'].replace(0, 1)
    
    # 비율 계산: (목표 2초 / 실제 시간)
    # 예: 10초 데이터면 0.2배로 줄임. 0.1초 데이터면 20배가 되는데 이를 1배로 제한(clip)함.
    scale_factor = TARGET_WINDOW_US / duration_us
    scale_factor = scale_factor.clip(upper=1.0) 

    # 2. 개수(Count) 관련 컬럼 스케일링
    # AI가 "2초 동안 발생할 양"으로 학습하도록 조정함
    count_columns = [
        'Total Fwd Packets', 
        'Total Backward Packets', 
        'Subflow Fwd Packets',
        'SYN Flag Count',
        'ACK Flag Count'
    ]

    for col in count_columns:
        if col in rescaled_df.columns:
            # 스케일링 적용
            rescaled_df[col] = rescaled_df[col] * scale_factor
            # 패킷 수는 정수여야 하므로 반올림 (최소 1개 이상 유지, 원본이 0이면 0)
            rescaled_df[col] = rescaled_df[col].apply(lambda x: max(1, round(x)) if x > 0 else 0)

    # 3. Flow Duration 보정
    # 탐지기가 2초마다 분석결과를 내므로, 모든 데이터의 Duration을 2초 근처로 정규화
    # 단, 원본이 2초보다 짧았던 것은 그대로 두거나 상한선만 2초로 맞춤
    rescaled_df['Flow Duration'] = rescaled_df['Flow Duration'].apply(lambda x: min(x, TARGET_WINDOW_US))
    
    # 4. 속도 및 평균 데이터 (Flow Packets/s, Flow IAT Mean 등)
    # 이 값들은 비율(Rate)이므로 원칙적으로 수정하지 않지만, 
    # 'Flow Packets/s'가 'Total Packets / Duration'으로 다시 계산되어야 하는 경우 아래처럼 처리 가능
    # 여기서는 원본 데이터의 특성을 유지하기 위해 그대로 둡니다.

    print(f"[Success] {len(rescaled_df)}개 행 스케일링 완료.")
    return rescaled_df

if __name__ == "__main__":
    try:
        # 데이터 로드
        df = pd.read_csv(INPUT_CSV)
        
        # 스케일링 실행
        new_df = rescale_to_window(df)
        
        # 저장
        new_df.to_csv(OUTPUT_CSV, index=False)
        print(f"[Done] 결과 저장 완료: {OUTPUT_CSV}")
        
        # 검증 출력
        print("\n[Check] 스케일링 결과 (평균값 비교):")
        cols_to_check = ['Total Fwd Packets', 'Flow Duration']
        for c in cols_to_check:
            if c in df.columns:
                print(f"- {c}: {df[c].mean():.1f} -> {new_df[c].mean():.1f}")
                
    except FileNotFoundError:
        print(f"[Error] {INPUT_CSV} 파일을 찾을 수 없습니다. 경로를 확인하세요.")
    except Exception as e:
        print(f"[Error] 예상치 못한 오류 발생: {e}")