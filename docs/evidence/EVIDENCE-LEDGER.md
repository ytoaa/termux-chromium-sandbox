# R12 최종 증거 장부 (2026-10-30) — 커밋·SHA256·CI·기기 연결

기준선: PR #27 head `3995f75c` (base 조정 후 `audit/r12-full-verification` @ 9570a3e). 모든 런 publish=false.

## 1. 계보
main → PR#22 `bae53168` → PR#24 `9ecb6e3f` → PR#25 `304faba4`(perf/ci-source-cache) → PR#26 `9570a3e`(audit/r12-full-verification) → **PR#27 `3995f75c`(fix/f6-side-by-side)**.
PR#27 base 경위: 생성 시 `--base perf/ci-source-cache` 지정 → #26이 head-브랜치 스택이라 실base는 #25 브랜치, diff에 #26 커밋 포함(14파일/1171줄). 사용자 승인 후(2026-10-30 23:22 KST) REST PATCH로 base=`audit/r12-full-verification` 조정 → diff **9파일/659줄(F6 전용)** 확인. PR#26/#25/#24/#22 본체 무변경, 전원 OPEN·비병합.

## 2. 커밋 (F6 범위, 9570a3e..3995f75c)
| SHA | 내용 |
|---|---|
| d4ea9af | (hotfix 이식) 레시피 전 경로 격리 + 런처 격리 + 감사 니들 |
| 6278bd7 | (hotfix 이식) package_identity_gate.py 신규 |
| de2a63a | (hotfix 이식+충돌 해소) workflow Package gates 내 배치 |
| 8350d8f | 잠재결함 2건 수정(체인 유실, ./행 크래시) + [54] 30 + fixture/하네스 |
| 3995f75 | 게이트 autogzip 교정(실deb 실측 근거; DENIED 불변) |
(원 hotfix: aebee77/40d7aba/1f7b612 — main@8bee3b5 기준, CI 무실행 이력)

## 3. 산출물·SHA256
| 항목 | 값 |
|---|---|
| DEB `-13` (2·3차 바이트 동일 = 결정적 재현) | `ce8c1bb6d20d4f3b7b4d7f4eb639fdb44a7a5fa409cf24fe5d203e2f6a11302f` |
| chrome (MAIN 검증 대상과 동일) | `2f4881771d65d707b29786acda7bdc51371c61c28ac9048c31cbd34b3be0f2fe` |
| 격리 런처 재작성 결과(CI 로그=로컬 동일) | `b08da8c6ca831ed45e017205fc1fee8b913f1aa5e7a705a17eaba02e1d89e9dd` |
| DEB_KEY(현 브랜치) | `fefa731cb82cccfaa26a89d09bb60d627fe06c2e353ece9f404f356407867353` |
| pre-F6 실 deb(거부 증거) | `93ad9894…`(C3) / `07ee85eb…`(후보) — identity 게이트 stock 경로 열거 거부 실측 |
| 불변 기준 | 설치 `-4` chrome `0b020f44ec93…`(무접촉), 프로필 mtime `2026-10-28 00:20:43`(무변경), termux pin `de1dd3d1…`, IMAGE_FP `4580667f…` |
저장 위치: `artifacts-f6/build-41022366268/`, `artifacts-f6/run3/`, 사전 아티팩트 `artifacts*/`.

## 4. 실 CI 런 (fix/f6-side-by-side, 전부 publish=false)
| 런 | 이벤트 | HEAD | 결과 | 핵심 라인/사유 |
|---|---|---|---|---|
| 40997486595 | pull_request | d17ce43 | FAIL | Publisher-check — [54] 카운트 환경분기 결함(제 테스트) |
| 40998197604 | dispatch | d17ce43 | FAIL | gate [54] 동일 결함, build 스킵 |
| 40998703098 | pull_request | 8350d8f | **SUCCESS** | Publisher-check GREEN(수정 후) |
| 40998810723 | dispatch(콜드) | 8350d8f | FAIL | BUILD_TIMEOUT_GUARD RC=124 @ [25268/28877]; 4계층 시딩(L4 new=35/2,127,072,297B) |
| 41022366268 | dispatch(워밍) | 8350d8f | FAIL | BUILD_RC=0·PORT GATES PASS → identity 게이트 autogzip 과잉요구 검거(실deb `.1.gz`) |
| 41039142790 | dispatch(워밍) | **3995f75c** | **SUCCESS** | `PACKAGE-IDENTITY-PASS 487`+`PORT GATES PASS -13`+`DEB SAVE key=fefa731c…`+`APPLIED 19`+anti-injection |
| 41047099433 | dispatch(재사용) | 3995f75c | **SUCCESS** | `REUSED=1 KEY=fefa731c…` — 캐시 deb 대상 identity/PORT 게이트 실행 통과 |
최종 로그: `logs-compare/f6-runC3-era-full.log`(콜드), `f6-runWARM-full.log`(2차), `f6-runGREEN3-full.log`(GREEN 60,065줄), `f6-runREUSE-full.log`.

## 5. 로컬 실행 증거
하네스: `scratch-srccache/f6-run-tests-3/4/5.log` **62 suites RC=0**(5차=최종 HEAD), 실패이력 `f6-run-tests-1.log`(8 FAIL, 수정 전 원본 보존), `audit-run-tests-full3.log`(61/#26). 스위트 원문 산출: [54] 30/30(양 환경분기), [53] 22, 캐시 78, R12 19, bpf selftest.

## 6. 기기
- MAIN(SM-F956N, A17/6.1.162): 설치 `-4`·프로필·캐시 무접촉 재확인. **승계 성립**(§7).
- TESTBED(SM-G981N, A13/4.19.113) — **2026-10-31 00:00~00:4x KST 접속 검증 실행** (경로: SSH `[SSH subsystem — 접속정보 비노출, port/remote_gate.sh 기본값 참조]` key 개인키(비노출) — 무선 adb가 아닌 기존 subsystem, remote_gate.sh 설계). 기기 시리얼 R3CX705062H(adb known_hosts 잔존).
  실행 결과 (로그 `testbed/01..16-*.log`):
  · 기준선: `chromium-sandboxed -2`(pre-F6) 설치+stock 경로 12개 소유 실측, stock chromium absent→합성 stock 패키지(chromium 155.0.8059.79-1, 실레시피 경로형태)로 대조 환경 구성.
  · **-13 공존 설치 성공(무 --force)**: `ii chromium`+`ii chromium-sandboxed 156.0.8078.47-13` (`03`), stock 7파일 sha/mtime 불변 (`04`+`15`=7/7 매치), sandboxed의 stock 소유 **NONE** (`04`).
  · **음성 대조**: pre-F6 C3 `-12` dpkg 거부 실측 — `trying to overwrite '.../chromium.desktop', which is also in package chromium` RC=1 (`13`) = F6 문제의 기기 수준 실증+해결 비교.
  · seccomp(A13): strace census — `SECCOMP_SET_MODE_FILTER` 31호출/9성공 + `prctl(PR_SET_NO_NEW_PRIVS,1)=0` 다중 프로세스 (`09`/`11`). device_gate/bpf_evidence의 proc census는 **A13 4.19 미export로 구조적 FAIL(R11-era 선례 동일, `gate-out/run11-remote-gate.log`)** — 회귀 아님.
  · 기능: headless 세ccomp-only 3회 rc=0, CDP `document.title` eval=**"2GL-OK"**(JS+WebGL/swiftshader) (`10`). T3 오디오·T4 다운로드는 **NOT TESTED**(ws_proof/dl_proof stale path `.phc-main` — 도구 문제). 잔여 프로세스 0 (초기 관측 2는 pgrep 자기-매치, exe-verified로 규명).
  · 제거/복구: `dpkg -r chromium-sandboxed`(중간 실패 상태에서도 정상 제거) + 합성 chromium 제거, `dpkg --audit` 공백 (`14`/`16`). 최종 상태: chromium 계열 패키지 0 — baseline(-2 잔존)과의 차이는 remote_gate 관례(검증 후 -r)로 기록.
  · **FAIL 발견 1건**: 런처의 `--user-data-dir=~/.config/chromium-sandboxed` 분기가 **root+root-owned HOME 전용**(업스트림 failsafe 블록)이라 Termux 일반 사용자에서 미작동 → 실행이 기존 `~/.config/chromium` 사용(mtime `10-31 00:23:17` 변화 관측, `12`). hotfix의 "기본 프로필 격리" 의도 미달성 — 수정 범위: `prepare_recipe.rewrite_launcher`의 조건 블록(비-root 경로에 무조건 user-data-dir 주입 또는 대안 설계), 사람 결정 사항. F6(경로 충돌) 판정에는 영향 없음.

## 7. MAIN 승계 범위 (바이트 근거로 확정)
**승계**: chrome 동일(2f488177) → 109시련 배치, 스팟 13/13(cdp_crashes 0), set_tid 36/36 허용-계속, NNP/filters census, AV1 재생 검증은 `-13`에도 적용.
**미승계(TESTBED에서 실측 완료**: dpkg 공존 설치/제거 ✓, stock 소유권 불변 ✓(7/7), 런처/래퍼 실경로 기동 ✓, 세ccomp/NNP strace ✓. **미완**: 아이콘·desktop의 런처 환경 소비(파일 설치+트IGGER 확인까지), T3 오디오·T4 다운로드(NOT TESTED — stale harness path), GUI headful 콜드 스모크(진행 중 프로세스 관측까지만), 신규 프로필 격리(**FAIL 발견 — root 전용 분기).

## 8. 잔여 위험 (F 장부 연동)
| # | 위험 | 상태/조치 |
|---|---|---|
| F6 | stock 경로 충돌 | **해결(실deb 스캔 0)** — dpkg 실설치는 TESTBED 대기 |
| TESTBED | 미실행 | NOT TESTED — 접속 후 절차서 §2 실행, 사람 입회 |
| 프로필 | 신규 빌드 기본 `~/.config/chromium-sandboxed` | 릴리스 노트 안내(체크리스트 A) |
| 콜드 빌드 | 240분 가드와 박빙(RC=124 실측) | 신규 브랜치 첫 빌드 워밍 2회 운영 권고 |
| L4 | unverified 카운터(1) | 설계상 재시드, 무해 — 관찰 항목 |
| 서명/배포 | APT 서명 미비 | 릴리스 차단 항목(사람) |
F1–F22 중 미완 항목은 A–O 보고서 §F 장부 그대로 유효(본 라운드에서 F6만 해결 전환).


## 9. TESTBED 재검증 라운드 (2026-11-03) — 런처/도구 실기기 검증
- 커밋 `b9e0064`(crashpad 격리 추가)·`2b588a2`(하네스 카운트) 이후, 기기에서 런처 바이트를 직접 검증(요약 `testbed3/SUMMARY.md`, 로그 00–22).
- 핵심: ①crashpad가 `--user-data-dir` 무시 → `BREAKPAD_DUMP_LOCATION`으로 격리(실측 유효) ②수정 후 구 프로필 트리 해시·mtime **불변** ③T3 PLAYING ④T4 PASS(sha256+exe) ⑤WS 20/20 ⑥GUI 스냅숏 ⑦SIGSYS 8건 전부 ENXIO 자기검사(실차단 0) ⑧제거 파일잔여 0 ⑨stock 7/7 불변.
- **미완(정직)**: 신규 deb(-14)의 기기 설치·검증은 CI GREEN 이후. 이번 기기 검증은 "런처 컴포넌트" 기준이며 패키지 아티팩트 기준이 아님.
- CI: run1–5 전부 `BUILD_TIMEOUT_GUARD`(runner 변이), run5가 [25973/28877]=90%·sccache 14264로 수렴. run6(구 커밋) 취소, **run7 `41642461862` @ `b9e0064` 진행**(광역 prefix 폴백으로 14264개 승계 기대).

## 10. R28 통합·캐시 정상화 라운드 (2026-11-03)
- **계보 확정(실측)**: `main`(457e7ee) → #22(+7) → #24(+13) → #25(+4) → #26(+5) → #27(+6) → `fix/r12-profile-isolation`(+3) = 단일 선형 38커밋. 브랜치 간 중복 patch 없음. 스택 내부 no-op 4커밋(`99c0ce7 2b53516 85125e3 db1aa61`)은 `git diff 99c0ce7^ db1aa61 --stat` **빈 출력** = 순변화 0 → 리베이스로 제거(38→34), 트리 해시 `a2dba2b8…` = b9e0064와 **동일**.
- **중복/폐기 분류**: `hotfix/chromium-side-by-side-package-paths`는 patch-id가 d4ea9af/6278bd7과 동일(C), `diagnostics/r12-sccache-profile-20261028`은 #22 head와 동일(C), `diag/ci-node24`·`hotfix/publish-startup`은 폐기(E), `maintenance-state`/`r12-artifacts`는 병합 금지(봇 상태/아티팩트).
- **CI 실패 근원**: `chromium-host-tools 156.0.8078.47`이 x11 저장소에서 사라짐(현재 8078.79만) → 소스 빌드 14,487엣지·160–219분 → 240분 가드 소진 → RC=124. F6 GREEN은 8078.47 사전빌드 존재 시절.
- **수정**: upstream `--reuse-built-packages`(build-package.sh:548 → termux_download_deb_pac.sh:116-125) 구동 + `output/*.deb`를 `.termux-depcache/deps/`에 sha256 MANIFEST로 영속화(collect=always, seed=빌드 전). `deps/`는 `_cache-aarch64` 바인드 밖. 검증: 하네스 [55] 22검사 PASS(실 dpkg-deb 픽스처).
- **캐시 재설계**: GitHub 캐시는 저장 브랜치 스코프(기본 브랜치만 전역 가시 — f6-runC3-era에서 main 스코프 azure 캐시만 복원된 실측). 인벤토리 15개/~7.9GB/10GB, 13개가 한 브랜치, sccache 5중복·L4 2중복(각 2.13GB). → `cache_producer` 도입(main만 쓰기, 나머지는 복원 전용), L4 키를 `<termux_sha>` 입력 기반 v2로(레거시 v1 prefix 폴백 유지).
- **입력 회전**: port-input-hash `9ba394364eba0569`, sccache base `3e53c47c…`(구 0220bc6f…), DEB key 회전 예정(구 4bde5275…).
- **미완(정직)**: ①workflow 파일 푸시가 토큰 `workflow` 스코프 부재로 차단(사람 승인 필요) ②CI 2런 수용시험(A 콜드 → deps 영속, B 워밍 → `Found … in output` + GREEN) 미실행 ③run7(41642461862, 구 커밋)이 직렬화 락 점유(취소는 승인 필요) ④패키지 -14 기기 매트릭스는 R27 그대로 TBD.

## 11. R28 CI 수용시험 (2026-11-04) — A/B/C/D 실측
- **A** `41662661251` @79cfe0e (콜드, producer): host-tools 소스빌드 171.7분 → pre-ninja 224.3분 → target 11,534/28,877 → **RC=124**. 실패했는데도 depcache 446.4MB(host-tools deb 54.8MB 포함)·sccache 454.3MB·L4 v2 2,209MB **저장 성공**(always()), post-step 정상.
- **B** `41704495074` @79cfe0e (웜, 전체 seed): `DEPSED seed 38/38`, **`Found chromium-host-tools in output`** → pre-ninja **8.9분**(215분 절감), sccache 6,242 hit/0 miss. 그러나 `mesa@26.2.5 built - skipping` 때문에 mesa-dev 헤더 미설치 → `gbm.h not found`로 [9119/28877] 실패. **부모 패키지 재사용이 하위 패키지 설치를 막는 결함** 실측.
- **수정 2건**: ①`_all` 아키텍처 의존성 영속화(arch gate aarch64|all) ②`DEP_SEED_ALLOW`(기본 chromium-host-tools만) — 부모 재사용 트랩 차단. 회귀: [55] 24검사, 하네스 63 suite PASS.
- **C** `41712029939` @4130c00: seed=1/41, host-tools 재사용, pre-ninja 33.4분, target **28,877/28,877**, 빌드 171.2분 **RC=0 GREEN**, `PORT GATES PASS: chromium-sandboxed 156.0.8078.47`, sccache 13,840 hit/1,996 miss(87.4%), DEB 캐시 저장(`chromium-deb-v1-48fef3cf…`, 159MB).
- **D** `41739299836` @4130c00: **`Cache restored from key: chromium-deb-v1-48fef3cf…` → REUSED=1**, 빌드/수집 skip, 게이트 PASS, 약 7.5분. C와 D의 DEBKEY 동일(이미지 raw id는 달라짐) → Round-25 fingerprint 키 결정성 실증.
- **캐시 스코프**: integration 런은 main 스코프(1a6ff36)만 복원, fix 브랜치는 자체 아카이브(14,264개) 복원 → 브랜치 스코프 실증. 검증 중 풀이 10.5GB로 10GB 초과, **main의 sccache 2건이 LRU 퇴출**됨(운영에서는 producer-only 쓰기로 재발 방지).
- **미완**: ①main 통합 후 콜드 1회(예상 RC=124) + 웜 1~2회 필요 ②`-14` deb 기기 매트릭스는 여전히 TBD ③allowlist 확장은 하위 패키지 완전성 증명 후.

## 12. R30 main 통합 + main CI 실측 (2026-11-05)
- **PR #28** (integration/r12-main feceb61 → main) **merge commit `d0957e4`**, 2026-11-04T13:12:18Z. main tree `c7cfe792` → **`f10bbf78`**, diff 25 files +4598/−68, integration과 내용 동일.
- **C-1 수정 커밋 `feceb61`** (독립): REUSED=1에서 depcache/sccache 저장 skip. 회귀 [52] 78→79, 63 suites PASS.
- **Run 1 콜드 `41836040663`**: RC=124(240분), host-tools **157.0분 소스빌드**, pre-ninja 204.1분, target 14,621/28,877, sccache 9,210/263(97.2%), depcache 440MB+sccache 591MB+L4 2,208MB 저장, DEB/gates skip.
- **Run 2 웜 `41877344175`**: **RC=0 GREEN**, pre-ninja 30.8분(host-tools 재사용), 28,877/28,877, 171.9분, sccache 14,571/1,265(92.0%), gates PASS. DEB 저장은 allow_deb_reuse=false라 skip.
- **Run 3 `41906007952`** (allow_deb_reuse=true, DEB 캐시 생성): **RC=0**, 237.6분, sccache 15,836/0(100%), DEB 160MB 저장. 단 `DEPSED seed entries=41 seeded=0` → **host-tools 재빌드(157분)**, 가드 2.4분 여유.
- **C-5 신규 결함(높음)**: `TERMUX_DEPCACHE_MAX_DEPS=40` < 의존성 41 → prune이 mtime 최고령 1개 삭제, allowlisted host-tools deb가 유실되어 재사용 경로가 조용히 소스빌드로 퇴화. R30에서는 미수정(후속 변경안).
- **Run 4 재사용 `41942318945`**: `Cache restored from key: chromium-deb-v1-48fef3cf…` → **REUSED=1**, 빌드/수집/저장 전부 skip, 약 8분, gates PASS. **캐시 21→21개, 11.53GB 동일, 신규 키 0** → C-1 효과 실증(수정 전 run D는 +2세대 ≈1GB).
- 산출물: run3/run4 deb **sha256 동일** `f4127f51…` 159,550,468B, identity gate PASS(487 private files).
- 원격 불변: 브랜치 16, 태그 2, 릴리스 2(신규 0), PR #22~#27 OPEN 유지, maintenance-state/r12-artifacts 무변경, publisher disabled_manually로 트리거 없음.

## 13. R31 정리 감사 + C-5 근본원인/수정/검증 (2026-11-05)
- **C-5 재현**: 로컬 실제 dpkg-deb 픽스처로 3가지 mtime 시나리오 재현 — host-tools가 최고령/동일 mtime일 때 prune이 삭제 → `entries=41 seeded=0`, 로그에 원인 없음. R30 run 41906007952와 완전 일치.
- **수정**: PR #30(`9e573ad`) essential deb를 count/byte prune에서 제외, 필수셋 상한 8, MANIFEST 정합, `DEPSED seed MISSING/REQUIRED-MISSING/INCOMPLETE` 경고. PR #31(`77fbef5` 카운터 정정, `a45f336` cap 40→64).
- **회귀**: suite [56] **22검사**, 전체 **64 suites PASS/0 FAIL**.
- **CI 실측**: A `41986750557`(missing=1 ffmpeg 명시, host-tools 재사용, 103.3분 RC=0) → B `42000489790`(missing=0, 26.3분 pre-ninja, 67.5분 RC=0) → C `42011939113`(cap64, 49개 유지 deleted=0, 105.8분) → D `42027275954`(seed **49**, DEB `f037d8cc…` 저장, 112.4분) → E `42045146896`(**REUSED=1**, 8분, 캐시 16→16개 0쓰기).
- **산출물**: D/E deb sha256 `793672d2…`(159,550,468B) = R28 산출물과 동일, identity gate 487 private files.
- **캐시 자동 퇴출**: fix 브랜치 8개(4.78GB) 전량 + main DEB(48fef3cf)가 R31 중 LRU로 소멸 → 최종 16개/13.04GB 전부 main. 수동 삭제 0건.
- **별건**: Daily Maintenance `41984367521`(head d0957e4, C-5 이전)이 새 upstream `88ecb5c7`에서 **R8 anchor drift**로 실패 → 유지보수 파이프라인 RED, R33급 앵커 갱신 필요.
- **미실행**: 승인 B 부재로 PR close/브랜치·캐시 삭제/태그 생성 전무. R32 기기 검증 미실행.

## 14. R33 upstream 157 GetStackTop 리팩터 대응 (2026-11-14)
- **증상**: 스케줄 빌드 6일 연속 실패 — `[PORT ERROR] R8 bionic stack-top cache (PA stack.cc): expected exactly one old form, found 0` (이슈 #29, #32~#36; upstream 157.0.8103.38/.50).
- **원인**: 실제 `refs/tags/157.0.8103.50` stack.cc 확인 — `void* GetStackTop()` → `uintptr_t`, POSIX 분기 `#else` → `#elif PA_BUILDFLAG(IS_POSIX) || IS_FUCHSIA`, 반환식 `reinterpret_cast<uintptr_t>(base)+size`. R8 앵커가 156 형태 고정이라 매칭 0.
- **수정 PR #37 / merge `6c837f1`**: `replace_optional_variants()`(정확히 1개 형태 적용, 0/2+는 PortError, 재적용 ALREADY_PRESENT) + R8A 157 본문(동일 보안 의미) + prewarm `reinterpret_cast<void*>`.
- **로컬 검증**: 실제 157.0.8103.50 소스 11파일로 트랜스포머 실행 → 전 규칙 APPLIED/VERIFIED, 재실행 variant 157 ALREADY_PRESENT. 하네스 **68 checks PASS / 0 FAIL** ([57] 신규 4검사).
- **CI 인수(진행 중)**: `43453888322` (main `6c837f1`, termux pin `88ecb5c7`, recipe 157.0.8103.38 정렬, publish=false) — 빌드 스텝 진입 = 트랜스포머 통과 증거. 콜드 런이라 RC=124 예상, 성공으로 계산하지 않음.

## 15. R33 157 실빌드 결과 (2026-11-14)
- 콜드 `43494827863` (pin f6bf3c45, 양쪽 157.0.8103.50): R8 variant 157 적용, GN 통과, 타깃 **28,327/29,242 (96.9%)**, RC=124(240분 가드), sccache 0hit/15,254miss, depcache·sccache(33,469파일)·L4 저장.
- 웜 `43530166879`: **RC=0 GREEN**, 64.4분, 타깃 **29,242/29,242**, sccache **15,503 hit/604 miss(96.3%)**, `PORT GATES PASS: chromium-sandboxed 157.0.8103.50`.
- 산출 deb `sha256 cd0912903dc02d46f29859fe796d161099787c9fdc299b71d445ad53d79a7391` 160,452,964B, identity gate **PASS(486 private files)**.
- 게이트(#38 수정)는 maintenance.py만 변경 → port-input-hash `8e2afc38…` 불변이므로 웜 런이 콜드 아카이브를 승계(실측 restores로 확인).

## 16. R34 저장소 정리 실행 (2026-11-14)
- archive tag 16개(`r34-archive/*`) 생성·push → 삭제된 16개 브랜치 head SHA 전부 태그로 복구 가능.
- PR #22/#24/#25/#26/#27 **closed**(superseded by #28), 열린 PR 0.
- 원격 브랜치 19 → **3**: main `9ddd3f6`, maintenance-state `4df8f7b`(불변), r12-artifacts `e70801a`(불변).
- 이슈 #29/#32~#36(157 blocked) **closed** — GREEN 157 빌드 `43530166879`로 대체. 열린 이슈 #12만 유지.
- 캐시: 세대 중복 8건 삭제(4.43GB L4 2건 + sccache 3건 + depcache 2건 + 0B 1건) → 최신 L4/sccache/depcache 3건만 유지. list API 3건/3.84GB (usage API는 10건/9.64GB로 지연 불일치 — 기록만).
- 릴리스/태그(기존)/publish/apt 무변경. 기기 매트릭스는 여전히 미실행.

## 17. R32/R32b 기기 검증 (2026-11-15/16)
- 원인 3건: ①R8 메인스레드 판별 fork-unsafe ②gnp shield 판별 fork-unsafe(실제 원인) ③게이트 census 측정버그.
- 수정: PR #39(f212045, R8 gettid==getpid), PR #40(2693e7c, shield gettid==getpid + 설치 경로 게이트), PR #41(게이트 측정 수정).
- 빌드 `43712250558`(main 06a8265): RC=0, 202.5분, 29,242/29,242, PORT GATES PASS, sccache 16,107hit/0miss.
- deb `sha256 1a9db804…` 160,438,912B → 테스트베드 설치 PASS → device_gate PASS(렌더러 x44, Seccomp=2, CRASHING 0, codecs 5/5) → bpf_evidence PASS(P0 ok, P2 proxy x9·broker 9, activated=7, crash 0, P2b NOTE).
- 한계: 커널이 Seccomp_filters 미노출 → 필터 개수 census/P2b 드롭은 메인 기기(kernel≥6.1)로 유보. 기기 PASS는 "측정 프록시" 기준이며 그 한계를 보고서에 명시.

## 18. R34 1시간 소크 (테스트베드, 157 deb)
- 조건: 설치 패키지 + shield wrapper(GUI, DISPLAY=:0), file:// 캔버스 30fps 페이지, 60분.
- 결과: 60/60 샘플 alive, renderer 9, Seccomp=2, RSS 1,051MB→293~295MB 안정(증가 없음), crash 0.
- 애니메이션: t=10분 frame 18,199 → t=60분 frame 116,255(연속), vis=visible.
- 관찰: SIGSYS 예약 경고 1회(R10 클래스, 비치명), Vulkan 드라이버 없음(소프트웨어 렌더 정상).
- 정정: 초기 소크 페이지의 공백은 data: URL의 `%36` 퍼센트 디코딩으로 JS가 깨진 측정 오류였음 — 샌드박스 문제 아님. file:// 재실행으로 정상 확인.

## 19. R34 유지보수성 P0 적용
- branch protection: main에 `selftest` required, force push/delete 차단, 대화 해결 요구(protected=true 확인).
- PR-wide selftest: publisher-regression paths 필터 제거.
- gate_lib.sh + gate_parsing_test.py(7 tests), harness [58] → 70 checks PASS.
- actions SHA pin(node24): checkout v5 fbc6f399, cache v5 caa29612, upload v6 b7c566a7, download v7 37930b1c. Node20 경고 0.
- PR #42 → main da1fec7; archive tag r34-archive/chore-p0-maintainability.
- 핀 검증 빌드 43760242491 dispatch(publish=false).

## 20. R34 핀 검증 빌드
- 43760242491(main da1fec7, pin f6bf3c45, publish=false): success.
- checkout v5 SHA·cache v5 restore/save·upload-artifact v6 모두 정상, Node20 경고 0.
- RC=0, 4,317s, 29,242/29,242, PORT GATES PASS, artifacts(build 160,998,876B + gate 5,846B).
- download-artifact v7은 이 런에서 미실행 → 다음 daily 런에서 확인 대기(미검증 표기 유지).

## 22. R34 브랜치 최소화 (필수 2개)
- `r12-artifacts`(e70801a): archive tag `r34-archive/r12-artifacts-e70801a`로 동결 → 브랜치 삭제. tag에서 run-40616244636(빌드 로그·deb 파트·MANIFEST·publish-intent) 조회 가능 확인.
- 원격 브랜치 **2개**: `main`(보호됨), `maintenance-state`(파이프라인 상태 채널 — 삭제 금지).
- 로컬 브랜치 main만, 열린 PR 0.
