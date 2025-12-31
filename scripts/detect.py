import time
import pandas as pd
import numpy as np
import joblib
import os
import sys
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ARP, conf
from collections import defaultdict

# ==========================================
# 설정 (Configuration)
# ==========================================
MODEL_PATH = 'models/multi_attack_ids_model.joblib'
WINDOW_SIZE = 2  # 분석 단위 (초)

# 모드 설정: "LIVE" (실시간 수집) 또는 "FILE" (pcap 파일 분석)
MODE = "FILE" 
TEST_PCAP_PATH = 'data/0_attack_by_once_ARP.pcap' 

# 최소 분석 패킷 수 (노이즈 방지)
MIN_PACKETS_THRESHOLD = 5

MODEL_COLUMNS = [
    'Flow Bytes/s', 'Flow Packets/s', 'Destination Port', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets', 'Flow IAT Mean',
    'Fwd Packet Length Mean', 'Max Packet Length', 'SYN Flag Count',
    'ACK Flag Count', 'Init_Win_bytes_forward', 'Active Mean',
    'Min Packet Length', 'Subflow Fwd Packets'
]

ATTACK_NAMES = {
    0: '🟢 정상 (Benign)',
    1: '🔍 포트 스캔 (PortScan)',
    2: '💥 DDoS 공격',
    3: '🤖 봇넷/브루트포스',
    4: '⚠️ ARP 스푸핑'
}

# ==========================================
# 1. 모델 로드
# ==========================================
print(f"[Init] 모델 로딩 중... ({MODEL_PATH})")
try:
    model = joblib.load(MODEL_PATH)
    print(f"[Init] 모델 로드 성공!")
except Exception as e:
    print(f"[Error] 모델 로드 실패: {e}")
    sys.exit(1)

# ==========================================
# 2. 특징 추출 함수
# ==========================================
def extract_features(packets):
    if not packets: return None

    start_time = float(packets[0].time)
    end_time = float(packets[-1].time)
    duration = end_time - start_time
    if duration <= 0: duration = 0.000001

    total_len = sum(len(p) for p in packets)
    max_len = max(len(p) for p in packets)
    min_len = min(len(p) for p in packets)
    
    syn_cnt = 0
    ack_cnt = 0
    dst_port = 0
    arp_count = 0

    # 1차 순회: ARP 패킷 여부 확인 (ARP가 있으면 포트를 무조건 0으로 고정하기 위함)
    for p in packets:
        if ARP in p:
            arp_count += 1
            dst_port = 0 
    
    # 2차 순회: ARP가 없을 때만 TCP/UDP 포트 추출
    if arp_count == 0:
        for p in packets:
            if TCP in p:
                dst_port = p[TCP].dport
                if 'S' in p[TCP].flags: syn_cnt += 1
                if 'A' in p[TCP].flags: ack_cnt += 1
            elif UDP in p:
                dst_port = p[UDP].dport

    iat_list = []
    for i in range(1, len(packets)):
        iat = float(packets[i].time - packets[i-1].time)
        if iat > 0: iat_list.append(iat * 1_000_000)

    num_pkts = len(packets)
    arp_ratio = arp_count / num_pkts

    features = {
        'Flow Bytes/s': total_len / duration,
        'Flow Packets/s': num_pkts / duration,
        'Destination Port': dst_port,
        'Flow Duration': duration * 1_000_000,
        'Total Fwd Packets': num_pkts,
        'Total Backward Packets': 0,
        'Flow IAT Mean': np.mean(iat_list) if iat_list else 0,
        'Fwd Packet Length Mean': total_len / num_pkts,
        'Max Packet Length': max_len,
        'SYN Flag Count': syn_cnt,
        'ACK Flag Count': ack_cnt,
        'Init_Win_bytes_forward': 0,
        'Active Mean': 0,
        'Min Packet Length': min_len,
        'Subflow Fwd Packets': num_pkts
    }

    return pd.DataFrame([features])[MODEL_COLUMNS], arp_ratio, dst_port

# ==========================================
# 3. 메인 로직
# ==========================================
def process_flow(pkts):
    if len(pkts) == 0: return
    
    flows = defaultdict(list)
    for pkt in pkts:
        if IP in pkt:
            flows[pkt[IP].src].append(pkt)
        elif ARP in pkt:
            # ARP 패킷은 보낸 사람의 IP 주소(psrc) 기준
            flows[pkt[ARP].psrc].append(pkt)

    for src_ip, flow_pkts in flows.items():
        if len(flow_pkts) < MIN_PACKETS_THRESHOLD: 
            continue
            
        result = extract_features(flow_pkts)
        if result is None: continue
        input_data, arp_ratio, actual_port = result

        try:
            pred = model.predict(input_data)[0]
        except Exception:
            continue
        
        # 패킷 뭉치 중 ARP 패킷이 단 하나라도 섞여 있다면 (arp_ratio > 0),
        # 그리고 AI가 '정상'이 아닌 다른 공격으로 분류했다면 무조건 ARP 스푸핑으로 간주
        if pred != 0 and arp_ratio > 0:
            pred = 4
        
        # 포트 스캔(1) 판단인데 패킷 수가 너무 적거나 ARP가 섞여있으면 보정
        if pred == 1 and (len(flow_pkts) < 15 or arp_ratio > 0):
            pred = 4 if arp_ratio > 0 else 0
        # -------------------------------------------

        if pred != 0:
            attack_name = ATTACK_NAMES.get(pred, "알 수 없음")
            print(f"\n" + "="*50)
            print(f"🚨 [경고] {attack_name} 감지!")
            print(f"   -> 공격자 IP/MAC: {src_ip} | 패킷 수: {len(flow_pkts)}")
            # 화면 출력 시에는 AI용 포트(0)가 아닌 실제 감지된 포트를 보여줌
            display_port = actual_port if actual_port != 0 else 0
            print(f"   -> PPS: {input_data['Flow Packets/s'].values[0]:.1f} | Port: {display_port} | ARP비율: {arp_ratio*100:.1f}%")
            print("="*50)

if __name__ == "__main__":
    if MODE == "FILE":
        print(f"[Mode] 파일 분석 모드: {TEST_PCAP_PATH}")
        if not os.path.exists(TEST_PCAP_PATH):
            print(f"[Error] 파일을 찾을 수 없습니다.")
            sys.exit(1)
        
        try:
            all_pkts = rdpcap(TEST_PCAP_PATH)
            print(f"[*] 총 {len(all_pkts)}개 패킷 분석 시작...")
            
            if len(all_pkts) > 0:
                start_ts = float(all_pkts[0].time)
                current_batch = []
                for p in all_pkts:
                    if float(p.time) - start_ts < WINDOW_SIZE:
                        current_batch.append(p)
                    else:
                        process_flow(current_batch)
                        start_ts = float(p.time)
                        current_batch = [p]
                process_flow(current_batch)
            print("\n[Done] 분석이 완료되었습니다.")
        except Exception as e:
            print(f"\n[Error] 오류: {e}")
    else:
        # 실시간 모드 (리눅스/라즈베리파이용)
        while True:
            try:
                pkts = sniff(timeout=WINDOW_SIZE)
                process_flow(pkts)
            except KeyboardInterrupt: break