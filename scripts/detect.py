import time
import pandas as pd
import numpy as np
import joblib
import os
import sys
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict

# 설정 (Configuration)
# 모델 파일 경로 (라즈베리파이 내 경로에 맞게 수정)
# 보통 detect.py가 scripts 폴더에 있으므로, 상위 폴더의 models를 찾습니다.
MODEL_PATH = 'models/multi_attack_ids_model.joblib'

# 분석 기준 시간 (초) - 2초 동안 패킷을 모아서 분석
WINDOW_SIZE = 2

# 학습 때 사용한 컬럼 순서 (순서가 틀리면 예측이 엉망이 됩니다)
MODEL_COLUMNS = [
    'Flow Bytes/s', 'Flow Packets/s', 'Destination Port', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets', 'Flow IAT Mean',
    'Fwd Packet Length Mean', 'Max Packet Length', 'SYN Flag Count',
    'ACK Flag Count', 'Init_Win_bytes_forward', 'Active Mean',
    'Min Packet Length', 'Subflow Fwd Packets'
]

# 공격 이름 매핑 (0~4번 라벨)
ATTACK_NAMES = {
    0: '정상 (Benign)',
    1: '포트 스캔 (PortScan)',
    2: 'DDoS 공격',
    3: '봇넷/브루트포스',
    4: 'ARP 스푸핑'
}

# 1. 모델 로드 (Model Loading)
print(f"[Init] 모델 로딩 중... ({MODEL_PATH})")

# 경로 문제 방지를 위한 절대 경로 처리
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
model_abs_path = os.path.join(base_dir, MODEL_PATH)

# 파일이 있는지 확인
load_path = MODEL_PATH
if not os.path.exists(MODEL_PATH):
    if os.path.exists(model_abs_path):
        load_path = model_abs_path
    else:
        print(f"[Error] 모델 파일이 없습니다!")
        print(f"  - 현재 경로: {os.getcwd()}")
        print(f"  - 찾는 경로: {MODEL_PATH}")
        print("PC에서 만든 'multi_attack_ids_model.joblib' 파일을 'models' 폴더에 넣어주세요.")
        sys.exit(1)

try:
    model = joblib.load(load_path)
    print(f"[Init] 모델 로드 성공! ({load_path})")
except Exception as e:
    print(f"[Error] 모델 로드 실패: {e}")
    sys.exit(1)

# 2. 특징 추출 함수 (Feature Extraction)
# Scapy 패킷 -> AI 입력 데이터 변환
def extract_features(packets):
    if not packets: return None

    # 시간 관련 계산
    start_time = packets[0].time
    end_time = packets[-1].time
    duration = end_time - start_time
    # 0으로 나누기 에러 방지
    if duration == 0: duration = 0.000001

    # 통계 변수 초기화
    total_len = 0
    max_len = 0
    min_len = 99999
    syn_cnt = 0
    ack_cnt = 0

    # 패킷 간격(IAT) 계산용
    iat_list = []
    prev_time = start_time

    # 패킷 하나하나 까보면서 특징 추출
    for pkt in packets:
        # 길이 통계
        length = len(pkt)
        total_len += length
        max_len = max(max_len, length)
        min_len = min(min_len, length)

        # 시간 간격 (IAT) - 마이크로초 단위
        iat = pkt.time - prev_time
        if iat > 0: iat_list.append(iat * 1_000_000)
        prev_time = pkt.time

        # TCP 플래그 카운트
        if TCP in pkt:
            flags = pkt[TCP].flags
            if 'S' in flags: syn_cnt += 1
            if 'A' in flags: ack_cnt += 1

    # 최종 특징 계산
    num_pkts = len(packets)

    # 학습 데이터와 동일한 15개 특징 생성 (순서 중요!)
    features = {
        'Flow Bytes/s': total_len / duration,
        'Flow Packets/s': num_pkts / duration,
        # 목적지 포트 (TCP/UDP 없으면 0)
        'Destination Port': packets[0][TCP].dport if TCP in packets[0] else (packets[0][UDP].dport if UDP in packets[0] else 0),
        'Flow Duration': duration * 1_000_000, # 마이크로초 단위
        'Total Fwd Packets': num_pkts,
        'Total Backward Packets': 0, # 단방향 수집 가정 (간소화)
        'Flow IAT Mean': np.mean(iat_list) if iat_list else 0,
        'Fwd Packet Length Mean': total_len / num_pkts,
        'Max Packet Length': max_len,
        'SYN Flag Count': syn_cnt,
        'ACK Flag Count': ack_cnt,
        'Init_Win_bytes_forward': 0, # Scapy로 추출하기 복잡하여 0으로 고정
        'Active Mean': 0,            # 복잡한 계산 제외
        'Min Packet Length': min_len,
        'Subflow Fwd Packets': num_pkts
    }

    # DataFrame으로 변환 (컬럼 순서 강제 적용)
    return pd.DataFrame([features])[MODEL_COLUMNS]

# 3. 메인 루프 (Main Loop)
if __name__ == "__main__":
    print("[Init] 실시간 네트워크 감시를 시작합니다. (Ctrl+C로 종료)")

    while True:
        try:
            print(f"\n[Listening] {WINDOW_SIZE}초간 패킷 수집 중...")

            # 1. 패킷 캡처 (타임아웃 동안 수집)
            pkts = sniff(timeout=WINDOW_SIZE)

            if len(pkts) == 0:
                continue

            # 2. IP별로 그룹화 (Flow 만들기)
            # 공격자는 보통 하나의 IP에서 집중적으로 패킷을 보냄
            flows = defaultdict(list)
            for pkt in pkts:
                if IP in pkt:
                    flows[pkt[IP].src].append(pkt)

            # 3. 각 IP(Flow)별로 분석 및 예측
            for src_ip, flow_pkts in flows.items():
                # 특징 추출
                input_data = extract_features(flow_pkts)
                if input_data is None: continue

                # 예측 (모델 사용)
                pred = model.predict(input_data)[0]

                # 결과 출력 (정상이 아닌 경우만 경고)
                if pred != 0:
                    attack_name = ATTACK_NAMES.get(pred, "알 수 없음")
                    print("="*50)
                    print(f"🚨 [경고] {attack_name} 감지!")
                    print(f"   -> 공격자 IP: {src_ip}")
                    print(f"   -> 패킷 수: {len(flow_pkts)}")
                    print(f"   -> 초당 패킷(PPS): {input_data['Flow Packets/s'].values[0]:.1f}")
                    print("="*50)

        except KeyboardInterrupt:
            print("\n[Exit] 프로그램을 종료합니다.")
            break
        except Exception as e:
            # 가끔 깨진 패킷 등으로 에러가 나도 멈추지 않도록 처리
            # print(f"[Warning] 분석 중 오류 발생: {e}")
            pass