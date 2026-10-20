# 나만의 여행경로

구글 계정 연동 없이 Google Maps API 키만으로 여행 경로를 만드는 정적 웹페이지입니다. (`public/index.html` 단일 파일, 빌드 불필요)

## 로컬 실행
```bash
python3 -m http.server 8000 -d public
```

## Cloudflare 배포 (Git 연동, Workers Builds)
- `wrangler.jsonc`의 `assets.directory`(`./public`)가 정적 파일 위치입니다. `name`은 Cloudflare Worker 이름과 같아야 합니다.
- 빌드 설정: Build command `exit 0`(또는 비움), Deploy command `npx wrangler deploy`
- `main`에 push하면 자동 배포됩니다. 발급된 `https://<이름>.<계정>.workers.dev` 주소를 API 키의 HTTP 리퍼러 제한에 `https://<주소>/*` 로 추가하세요.

## API 키
키는 코드에 포함되지 않으며 각 사용자가 첫 화면에서 입력합니다(브라우저 localStorage에만 저장).
