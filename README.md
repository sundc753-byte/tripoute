# 나만의 여행경로

구글 계정 연동 없이 Google Maps API 키만으로 여행 경로를 만드는 정적 웹페이지입니다. (`public/index.html` 단일 파일, 빌드 불필요)

## 구조
- `public/` : 화면(`index.html` 지도, `login.html` 로그인·가입, `admin.html` 회원 승인), `config.js`(지도 API 키)
- `src/worker.js` : 회원가입 / 로그인 / 관리자 승인 API + 정적 파일 접근 제어 (Cloudflare Workers + D1)
- `wrangler.jsonc` : 배포 설정 (D1 바인딩 `DB`, 관리자 이메일 `ADMIN_EMAIL`)

모든 요청은 Worker를 먼저 거치며, **로그인한 승인 사용자**에게만 지도 화면과 `config.js`(API 키)를 내려줍니다.

## 인증 흐름
1. 사용자가 이메일·비밀번호로 가입 → `pending`(승인 대기)
2. 관리자가 `/admin`에서 승인하면 로그인 가능 (거절·삭제 시 기존 로그인도 즉시 무효)
3. 비밀번호는 PBKDF2-SHA256(100,000회, 사용자별 salt)으로 해시해 저장, 세션은 HttpOnly 쿠키(30일)
4. 로그인 5회 실패 시 15분 제한, IP당 가입 시간당 5회 제한

## Cloudflare 최초 설정
1. **D1**: `wrangler.jsonc`의 `d1_databases`는 `database_id` 없이 선언돼 있어 배포 시 자동 생성됩니다. 자동 생성이 안 되면 대시보드 Storage & Databases → D1에서 `tripoute-db`를 만들고 Worker의 Bindings에 변수명 `DB`로 연결하세요. 테이블은 첫 요청 때 자동 생성됩니다.
2. **관리자 설정 코드(비밀값)**: Worker → Settings → Variables and Secrets → Add → Type `Secret`, 이름 `ADMIN_SETUP_CODE`, 값은 직접 정한 긴 문자열
3. 배포 후 `/login` → 회원가입 탭 → 하단 "관리자 계정 만들기"를 눌러 `sundc753@gmail.com`, 비밀번호, 설정 코드를 입력해 관리자 계정을 만듭니다. (이후 설정 코드는 일반 가입에 영향을 주지 않습니다.)

## 로컬 실행
Node 설치 후 `npx wrangler dev` (로컬 D1이 자동 사용됩니다). 관리자 코드는 `.dev.vars` 파일에 `ADMIN_SETUP_CODE=...`로 둡니다(커밋 금지, `.gitignore`에 포함).

## Cloudflare 배포 (Git 연동, Workers Builds)
- Build command `exit 0`(또는 비움), Deploy command `npx wrangler deploy`
- `main`에 push하면 자동 배포됩니다.
- 발급된 `https://<이름>.<계정>.workers.dev` 주소를 API 키의 HTTP 리퍼러 제한에 `https://<주소>/*` 로 추가하세요.

## API 키
`public/config.js`의 `TRIPOUTE_API_KEY`에 공용 키를 넣으면 승인된 사용자는 키 입력 없이 지도를 씁니다. 비워 두면 각자 키를 입력합니다.
