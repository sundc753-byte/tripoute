# 나만의 여행경로

구글 계정 연동 없이 Google Maps API 키만으로 여행 경로를 만드는 정적 웹페이지입니다. (`index.html` 단일 파일, 빌드 불필요)

## 로컬 실행
```bash
python3 -m http.server 8000
```

## Cloudflare Pages 배포 (Git 연동)
1. 이 저장소를 GitHub에 push
2. Cloudflare 대시보드 → Workers & Pages → Create → Pages → Connect to Git → 저장소 선택
3. Build settings: Framework preset `None`, Build command 비움, Build output directory `/`
4. Save and Deploy → `https://<프로젝트>.pages.dev` 발급
5. Google Cloud Console에서 API 키의 HTTP 리퍼러 제한에 `https://<프로젝트>.pages.dev/*` 추가 (커스텀 도메인 사용 시 해당 도메인도)

이후 `main`에 push하면 자동 배포되고, 다른 브랜치는 미리보기 URL이 생성됩니다.

## API 키
키는 코드에 포함되지 않으며 각 사용자가 첫 화면에서 입력합니다(브라우저 localStorage에만 저장).
