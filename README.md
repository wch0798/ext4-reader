# EXT4 Reader for Windows

사용자용 설명서는 **[사용설명서.md](사용설명서.md)** 를 보세요.

HDD, SSD, USB, SD 카드의 **EXT4** 파티션을 **Windows 탐색기 드라이브**로 연결합니다. 연결되면 내 PC에 `G:` 같은 드라이브가 생기고, 평소처럼 복사·붙여넣기·삭제·새 폴더를 쓰면 됩니다.


## 처음 한 번만

1. [Python 3.10+](https://www.python.org/downloads/)
2. 의존성:

```bat
python -m pip install -r requirements.txt
```

탐색기 연결에 필요한 **WinFsp**는 프로그램이 없으면 자동으로 받아 설치합니다. 관리자 확인 창이 뜨면 허용하세요. 설치 직후 드라이버가 안 켜지면 PC를 한 번 재시작하면 됩니다.\n\n일부 USB 카드리더가 Windows raw-write를 전부 거부하면 **UsbDk가 필요하다는 안내가 자동으로 뜹니다.** 사용자가 설치를 승인하면 공식 UsbDk MSI를 자동 다운로드하고 SHA-256을 검증한 뒤 자동 설치합니다. 일반 리더기에는 UsbDk를 사용하지 않습니다.

## 실행

물리 디스크(내장 HDD, SD 카드)는 **관리자 권한**이 필요합니다.

1. `run_as_admin.bat` 실행
2. 목록에서 EXT4 볼륨을 선택
3. **탐색기에서 열기** (또는 더블클릭)
4. 내 PC에 나타난 드라이브로 파일을 다루기
5. 작업이 끝나면 **연결 해제**. 프로그램 창을 닫아도 드라이브는 사라집니다.

이미지만 열려면 `run.bat` 로도 됩니다.

## 쓰는 법

- 읽기: 탐색기에서 파일을 열거나 Windows 폴더로 **끌어다 놓기**
- 쓰기: 상단 **쓰기 허용** 을 켠 뒤 볼륨을 **다시 연결**하고, 탐색기에서 넣기/삭제/이름 바꾸기/**드래그 앤 드롭**

리눅스가 그 파티션을 마운트한 상태에서는 쓰지 마세요. 저널이 더럽거나 암호화 등이 있으면 읽기 전용으로만 연결됩니다.

## 권한

| 대상 | 탐색기 연결 | 쓰기 |
| --- | --- | --- |
| HDD / SSD / USB / SD | 관리자 + WinFsp | 쓰기 허용 |
| `.img` / `.raw` 파일 | WinFsp | 쓰기 허용 |


## 소스 구조

소스는 별도 `ext4reader/` 패키지 복사본 없이 **저장소 루트 한 곳**만 사용합니다.

- `main.py`: 실행 진입점
- `gui.py`, `windows_disk.py`, `volume.py`, `journal.py` 등: 핵심 모듈
- `tests/`: 회귀 테스트
- `Ext4Reader.spec`: PyInstaller 빌드 정의
- `Ext4Reader.exe`: GitHub Actions가 최신 소스로 자동 생성한 실행 파일

소스 실행은 `python main.py` 또는 `run_as_admin.bat`을 사용합니다.
