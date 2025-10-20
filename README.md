워드프레스 플러그인 정적 취약점 스캐너 (Semgrep 기반)

개요

- 목표: Semgrep의 정규표현식(rule) 기반으로 워드프레스 플러그인 코드의 흔한 보안 취약 패턴을 탐지하고, 간단한 리포트를 생성합니다.
- 구성: rules(규칙), scanner(실행 스크립트), plugins(스캔 대상), plugins_zips(수집된 zip), results(결과물)

폴더 구조

- `rules/wordpress-regex.yaml`: 워드프레스 플러그인 취약점 탐지를 위한 정규표현식 규칙 모음
- `scanner/wp_scanner.py`: 플러그인 수집(압축 해제), 스캔 실행, 리포트 생성을 위한 CLI
- `plugins/`: 스캔할 플러그인 폴더(압축 해제된 상태)
- `plugins_zips/`: 수집된 플러그인 zip 파일을 넣는 폴더
- `results/`: 스캔 결과(JSON/CSV/Markdown)

사전 준비

1. Python 3.9 이상
2. Semgrep 설치 (로컬 PATH에 필요)
   - pipx: `pipx install semgrep`
   - pip: `pip install --user semgrep`
   - PowerShell: `scoop install semgrep` 또는 `choco install semgrep`

사용 방법

1. 플러그인 수집(압축 해제)

   - 워드프레스 플러그인 zip 파일을 `plugins_zips/`에 넣습니다.
   - 실행: `python scanner/wp_scanner.py ingest -z plugins_zips -p plugins --clear`
     - `--clear`는 기존 `plugins/` 폴더를 비운 뒤 다시 추출합니다.

2. 스캔 실행

   - 실행: `python scanner/wp_scanner.py scan -p plugins -r rules -o results`
   - 결과: `results/semgrep.json`(원본), `results/semgrep.filtered.json`(간단 히ュー리스틱 필터 적용)

3. 요약 리포트 생성
   - 실행: `python scanner/wp_scanner.py report -i results/semgrep.filtered.json -p plugins -o results`
   - 결과: `results/report.md`, `results/summary.csv`

탐지 규칙

- 위험한 실행: `eval`, `assert`, `preg_replace(/e/)`, `create_function`
- 역직렬화: `unserialize($_GET/POST/REQUEST/COOKIE/...)`
- 파일 포함/접근: `include/require` 및 파일 I/O에 사용자 입력 사용 (LFI/경로조작)
- 업로드 처리: `move_uploaded_file` 존재 시 수동 검토(확장자/타입 검증 필요)
- 데이터베이스: `$wpdb->query/get_*`에서 사용자 입력 사용 또는 문자열 연결(SQLi 위험) – `prepare()` 미사용 의심
- XSS: `echo/print/printf/die/exit`에서 사용자 입력 출력 (escape 미적용)
- SSRF: `wp_remote_get/post/request/head`에 사용자 입력 사용
"# WP-Plugin-Scanner" 
