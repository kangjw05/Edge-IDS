import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP
import os

# ==========================================
# 설정
# ==========================================
INPUT_PCAP = 'data/0_attack_by_once_ARP.pcap' # 경로 다시 확인
OUTPUT_CSV = 'data/ARP_Spoofing_Final_Data.csv'
WINDOW_SIZE = 2  
AUGMENT_COUNT = 5000  # ARP 데이터를 5,000줄로 복사 (데이터 불균형 해결)

MODEL_COLUMNS = [
    'Flow Bytes/s', 'Flow Packets/s', 'Destination Port', 'Flow Duration',
    'Total Fwd Packets', 'Total Backward Packets', 'Flow IAT Mean',
    'Fwd Packet Length Mean', 'Max Packet Length', 'SYN Flag Count',
    'ACK Flag Count', 'Init_Win_bytes_forward', 'Active Mean',
    'Min Packet Length', 'Subflow Fwd Packets', 'Label'
]

def process_pcap(pcap_file):
    print(f"[Process] PCAP 읽는 중: {pcap_file}")
    if not os.path.exists(pcap_file):
        print(f"[Error] 파일이 없습니다: {pcap_file}")
        return None

    packets = rdpcap(pcap_file)
    if not packets:
        print("패킷이 없습니다.")
        return None

    features_list = []
    start_time = float(packets[0].time)
    current_batch = []
    
    for pkt in packets:
        pkt_time = float(pkt.time) # float으로 변환하여 Decimal 에러 방지
        if pkt_time - start_time <= WINDOW_SIZE:
            current_batch.append(pkt)
        else:
            features = extract_from_batch(current_batch)
            if features:
                features_list.append(features)
            start_time = pkt_time
            current_batch = [pkt]
            
    if current_batch:
        features = extract_from_batch(current_batch)
        if features:
            features_list.append(features)

    df = pd.DataFrame(features_list)
    
    # --- 데이터 증폭 (Oversampling) ---
    if len(df) > 0:
        print(f"[Info] 추출된 ARP 데이터 {len(df)}줄을 {AUGMENT_COUNT}줄로 증폭합니다.")
        df = pd.concat([df] * (AUGMENT_COUNT // len(df) + 1), ignore_index=True)
        df = df.iloc[:AUGMENT_COUNT] # 정확히 목표치만큼 자름
        
    return df

def extract_from_batch(batch):
    if not batch: return None
    
    # Scapy 시간 데이터를 float으로 명시적 변환 (에러 해결 핵심)
    duration = float(batch[-1].time) - float(batch[0].time)
    if duration <= 0: duration = 0.001
    
    total_len = sum(len(p) for p in batch)
    iat_list = []
    for i in range(1, len(batch)):
        # 모든 시간 계산을 float으로 처리
        iat = (float(batch[i].time) - float(batch[i-1].time)) * 1_000_000
        iat_list.append(iat)
        
    syn_cnt = 0
    ack_cnt = 0
    for p in batch:
        if TCP in p:
            flags = str(p[TCP].flags)
            if 'S' in flags: syn_cnt += 1
            if 'A' in flags: ack_cnt += 1
            
    num_pkts = len(batch)
    
    feat = {
        'Flow Bytes/s': float(total_len / duration),
        'Flow Packets/s': float(num_pkts / duration),
        'Destination Port': int(batch[0][TCP].dport) if TCP in batch[0] else (int(batch[0][UDP].dport) if UDP in batch[0] else 0),
        'Flow Duration': float(duration * 1_000_000),
        'Total Fwd Packets': int(num_pkts),
        'Total Backward Packets': 0,
        'Flow IAT Mean': float(np.mean(iat_list)) if iat_list else 0.0,
        'Fwd Packet Length Mean': float(total_len / num_pkts),
        'Max Packet Length': int(max(len(p) for p in batch)),
        'SYN Flag Count': int(syn_cnt),
        'ACK Flag Count': int(ack_cnt),
        'Init_Win_bytes_forward': 0.0,
        'Active Mean': 0.0,
        'Min Packet Length': int(min(len(p) for p in batch)),
        'Subflow Fwd Packets': int(num_pkts),
        'Label': 'ARP'
    }
    return feat

if __name__ == "__main__":
    df_arp = process_pcap(INPUT_PCAP)
    if df_arp is not None:
        # data 폴더가 없으면 생성
        os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
        df_arp.to_csv(OUTPUT_CSV, index=False)
        print(f"[Success] ARP 데이터 생성 및 증폭 완료: {OUTPUT_CSV} ({len(df_arp)} lines)")