import pandas as pd
import joblib
import os
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# 설정
DATA_FILE = "data/Final_Normalized_Training_Data.csv"
MODEL_DIR = "models"
MODEL_FILE = os.path.join(MODEL_DIR, "multi_attack_ids_model.joblib")

# 모델 저장 폴더가 없으면 생성
if not os.path.exists(MODEL_DIR):
    os.makedirs(MODEL_DIR)

# 1. 데이터 로드
print(f"데이터 로드 중: {DATA_FILE}...")
if not os.path.exists(DATA_FILE):
    print("[오류] 데이터 파일이 없습니다. gather_dataset.py를 먼저 실행하세요.")
    exit()

df = pd.read_csv(DATA_FILE)

# 2. 데이터 분리 (문제지와 정답지)
# Target 컬럼이 정답(Label), 나머지는 문제(Features)
X = df.drop(columns=['Target'])
y = df['Target']

print(f"학습 데이터 크기: {len(df)}")
print(f"특징(Feature) 개수: {X.shape[1]}")

# 훈련용(80%)과 테스트용(20%)으로 분리
# stratify=y: 정답 비율을 유지하면서 나눔 (공격 데이터가 적을 때 필수)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

# 3. LightGBM 모델 학습
print("모델 학습 시작 (LightGBM)...")

# 다중 분류(Multiclass) 설정
model = LGBMClassifier(
    objective='multiclass',   # 다중 분류 모드
    num_class=5,              # 클래스 개수 (0~4)
    n_estimators=200,         # 나무의 개수 (많을수록 정확하지만 느려짐)
    learning_rate=0.1,        # 학습률
    random_state=42,
    verbose=-1                # 경고 메시지 숨김
)

model.fit(X_train, y_train)
print("학습 완료!")

# 4. 성능 평가
print("\n[성능 평가 리포트]")
y_pred = model.predict(X_test)

# 사람이 알아보기 쉬운 이름
target_names = ['Benign(0)', 'PortScan(1)', 'DDoS(2)', 'Botnet(3)', 'ARP(4)']

# 실제 정답에 존재하는 클래스만 이름 매핑 (혹시 데이터가 부족해서 클래스가 빠졌을 경우 대비)
unique_labels = sorted(list(set(y_test) | set(y_pred)))
target_names_subset = [target_names[i] for i in unique_labels]

print(classification_report(y_test, y_pred, target_names=target_names_subset, digits=4))



# 5. 모델 저장
joblib.dump(model, MODEL_FILE)
print(f"모델 저장 완료: {MODEL_FILE}")