# R34 — GitHub 프로젝트 유지보수성 평가 (읽기 전용 감사)

기준 시점: main `b13c8ec` (2026-11-16 01:25 KST). 코드/CI/이슈/브랜치/캐시 상태를 실제 조회한 결과만 사용.

## 1. 규모와 구조

| 항목 | 값 |
|---|---|
| 저장소 | 106 files, pack 128.9 KiB (코드 중심, 경량) |
| 포트 코드 | 5,716 LOC (transformer 850, maintenance 846, ci/prepare/shim/gates 포함) |
| 문서 | README 9 KB, DESIGN.md 132 KB(2,159줄), REGRESSION.md 14.6 KB |
| 테스트 | 15 suite, harness 69 checks + maintenance 73 + cache-layers 81 |
| 워크플로 | build / daily-maintenance / publish-release / publisher-regression |
| 원격 브랜치 | 3 (`main`, `maintenance-state`, `r12-artifacts`) |
| 열린 PR / 이슈 | 0 / 1(#12 운영 트래커) |
| 태그/릴리스 | archive 19 + 기존 2, 릴리스는 156 pre-release 2건 |

## 2. 차원별 점수 (10점 만점, 주관 평가)

| 차원 | 점수 | 근거 |
|---|---|---|
| 코드 구조/모듈성 | **7.5** | R1–R12 규칙 + fail-closed `PortError`, 156/157 shape-aware 변형, 관심사 분리 양호. 단일 transformer 850줄·문자열 앵커 의존은 취약. |
| 테스트 깊이 | **7.5** | 실제 upstream shape fixture, 멱등/실패폐쇄/보안 불변식 검증. **기기 게이트 스크립트 파싱 테스트 부재**(이번 라운드 3건 버그 발생). PR에서 컴파일 검증 없음. |
| CI 신뢰성/관측성 | **6** | 최근 빌드 13/18 성공(72%), 최근 5회 중 3 GREEN. 그러나 daily-maintenance 최근 12회 **5성공/7실패(42%)**, 빌드 44–203분·콜드 240분 가드로 피드백 루프 김. 수동 dispatch 의존. |
| 문서화 | **7** | DESIGN.md가 라운드별 원인·수정·검증을 매우 상세히 기록. 단 132KB 단일 문서로 비대, 증거 원장은 저장소 밖(`~/Project/chromium-evidence`)에 있음. |
| 업스트림/의존성 회복력 | **6.5** | 157 드리프트를 게이트로 fail-closed 처리하고 shape 변형으로 흡수. 하지만 핀 갱신 수동, actions v4/v7 태그(일부 Node20 deprecation 경고) 노후. |
| 저장소 위생/프로세스 | **7.5** | 브랜치 3·PR 0·이슈 1, archive tag로 삭제 head 보존. **main 브랜치 보호 없음**(required checks 없음), 릴리스 156에 정체. |
| 운영/버스 팩터 | **5** | 단일 유지보수자 + 단일 테스트베드 + 자격증명 민감 + 장시간 수동 검증. `Seccomp_filters` 미노출 커널로 프록시 측정 의존. |

**종합: 약 7/10 (B)** — “잘 관리된 소규모 포트 프로젝트, 자동화·보호장치가 한 단계 더 필요”.

## 3. 강점
1. **fail-closed 설계**: 규칙 불일치 시 `PortError`, 게이트 실패 시 캐시 저장 중단, publish fail-closed.
2. **보안 불변식 테스트**: Allow()/BPF 정책 토큰 금지, R8 캐시 의미, SIGSYS 예약 등 하네스가 고정.
3. **upstream 드리프트 대응 체계**: 156/157 shape 변형 + 실제 소스 fixture + `upstream-recipe-not-ready` 게이트로 4시간 낭비 방지.
4. **캐시 키 규율**: `port-input-hash`(v2)로 코드 변경만 회전, maintenance-only 커밋은 승계 — 문서화·검증됨.
5. **낮은 PR/브랜치 부채**: 열린 PR 0, 브랜치 3, archive tag 19로 감사 추적 보존.
6. **상세한 라운드 문서**: DESIGN.md·REGRESSION.md·evidence ledger로 재현 가능.

## 4. 주요 리스크 (우선순위)
| # | 리스크 | 근거/영향 | 완화 |
|---|---|---|---|
| R1 | main 무보호 | required checks 없음 → 직접 push/강제 push 가능 | branch protection + Publisher Regression required |
| R2 | 게이트 스크립트 무테스트 | R32에서 census prefix/런처 경로/filter fallback 3건 버그 | fake /proc fixture 단위 테스트, `ci.sh gates-smoke` |
| R3 | daily-maintenance 신뢰도 | 최근 12회 42% 성공, 실패 시 4시간 소모 | 실패 사유 텔레메트리 강화, 러너 시간 단축(캐시 워밍 전용 nightly) |
| R4 | 긴 피드백 루프 | 빌드 44–203분, 콜드 240분 가드 | PR 단계 transformer dry-run + nightly producer(게시 없음) |
| R5 | 단일 기기/버스 팩터 | 테스트베드 1대, 커널이 Seccomp_filters 미노출 | 메인 기기(kernel≥6.1) census, 기기 매트릭스 자동 스크립트화 |
| R6 | 문서 비대/증거 분리 | DESIGN 132KB, evidence 저장소 밖 | docs/ 분할, evidence 원장 저장소 내 요약본 |
| R7 | actions 노후 | v4/v7 태그, Node20 deprecation 경고 | Node24 호환 버전 + SHA pin |
| R8 | 캐시 LRU | 10GB 예산, R31에서 fix 브랜치 캐시 8건 소실 | 8GB 초과 알림, 핵심 레이어 고정 정책 |
| R9 | 릴리스 정체 | 릴리스 156, 157은 pre-release 없음 | 릴리스 체크리스트(기기 PASS+승인) 자동화 |

## 5. 권고 (효과/노력)
- **P0 (1–2주)**: ①main branch protection ②게이트 스크립트 단위 테스트 ③actions Node24 호환+pin.
- **P1 (2–4주)**: ④evidence 요약본 저장소 내 `docs/evidence/` ⑤DESIGN 분할(architecture / invariants / rounds) ⑥nightly cache-warm producer(publish=false) ⑦캐시 8GB 경보.
- **P2 (1–2개월)**: ⑧termux 핀 자동 PR(recipe==host-tools일 때) ⑨메인 기기 filter-count census로 프록시 은퇴 ⑩릴리스 체크리스트 자동화.

## 6. 결론
유지보수성은 **양호하나 “1인 운영 + 긴 루프 + 무보호 main”** 이 최대 약점이다. 코드/테스트/문서의 질은 높고, 이번 라운드에서 드러난 게이트 측정 버그를 수정·검증한 것은 유지보수 관점의 긍정 신호다. P0 3개만 적용해도 운영 리스크가 체감적으로 줄어든다.

## 7. P0 적용 결과 (2026-11-15/16, main `da1fec7`)

| P0 항목 | 상태 | 근거 |
|---|---|---|
| main branch protection | **APPLIED** | required check `selftest`, force push/delete 차단, 대화 해결 요구, `enforce_admins=false`. API GET으로 protected=true 확인 |
| PR-wide selftest | **APPLIED** | publisher-regression paths 필터 제거 → 모든 PR에서 selftest 실행(PR #42에서 GREEN, 1분대) |
| gate parsing 단위 테스트 | **APPLIED** | `port/gate_lib.sh` 추출 + `port/tests/gate_parsing_test.py` 7 tests, harness `[58]`. 전체 **70 checks PASS/RC=0** |
| actions Node24 + SHA pin | **APPLIED** | checkout v5 `fbc6f399…`, cache v5 `caa29612…`, upload-artifact v6 `b7c566a7…`, download-artifact v7 `37930b1c…`; Node20 deprecation 경고 0건(PR 런 로그 확인) |
| 결함 하드닝 | 부수 | `gate_decide`가 필터 export 여부와 무관하게 **CRASHING>0이면 FAIL** |

PR #42 (`666ac50`) → merge `da1fec7`, 브랜치 archive tag `r34-archive/chore-p0-maintainability` 보존 후 삭제.

핀 검증용 빌드 `43760242491`(main `da1fec7`, pin f6bf3c45, publish=false)를 dispatch함 — 완료 시 §8에 결과를 추가한다.

## 8. 핀 액션 검증 빌드 결과 (43760242491)

main `da1fec7`, pin `f6bf3c45` (157.0.8103.50), publish=false:

    checkout (v5 SHA)        : completed
    cache/restore (v5) x2    : "Cache restored from key" (sccache b29af538…-43712250558, depcache)
    build                    : RC=0, 4,317 s (71.9 min), [29242/29242], PORT GATES PASS
    cache/save (v5) x3       : Save termux dep cache / Save sccache / Save source cache = success
    upload-artifact (v6)     : build artifact 160,998,876 B + gate artifact 5,846 B uploaded
    Node.js 20 deprecation   : 0 warnings (전 런로그)
    결론                     : success (completed success)

미검증 1건: `download-artifact` v7은 daily-maintenance/publish-release에서만 쓰이므로
이번 런에서는 실행되지 않았다 — 다음 스케줄 daily 런에서 확인한다(미검증을 PASS로
대체하지 않음).
