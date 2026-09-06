# Spring Security + JWT 인증/인가

적용 대상은 실행 프로젝트 `Backend`다. `original/Back-end`는 이전 스냅샷이므로 수정하지 않는다.

## 구현과 API 계약

`WebConfig`와 `OpenApiPointInterceptor`를 삭제했다. `x-user-id`는 인증이나 포인트 지급에 사용되지 않는다. 로그인 검증은 `AuthService`로 통합했으며, 기존 UserService/AdminService의 로그인 메서드를 제거했다. USER와 ADMIN은 별도 계정 저장소로 검증한다. 요청 DTO에서 Role/Authority를 받아 권한을 올릴 수 없다.

| 요청 | 입력 | 성공 응답 |
| --- | --- | --- |
| POST `/users/login` | `{"userId":"alice","password":"..."}` | 토큰 쌍 |
| POST `/api/admin/login` | `{"adminId":1,"password":"..."}` | 토큰 쌍 |
| POST `/auth/refresh` | `{"refreshToken":"..."}` | 회전된 토큰 쌍 |
| POST `/auth/logout` | 현재 Access Token의 Bearer 헤더 | 204 |

토큰 쌍: `accessToken`, `refreshToken`, `expiresIn`(초), `tokenType`(`Bearer`). 로그인/재발급 응답에는 `Cache-Control: no-store`를 적용한다. 기존 프로필 중심 로그인 응답과 계약이 달라졌으므로 앱에서도 이 필드들을 저장하고 보호 요청마다 `Authorization: Bearer <accessToken>`을 보낸다. 만료 Access Token은 refresh 요청에 붙이지 않는다. `permitAll`도 JWT 필터를 통과하므로 잘못된 토큰을 보내면 401이다.

JWT는 HS256 서명, issuer=`peticle`, audience=`peticle-api`, `sub`, `jti`, `sid`, `role`, `type`, `iat`, `exp`를 사용한다. 검증기는 서명/알고리즘/issuer/audience/type/필수 식별자/만료를 검증한다. Refresh Token을 Access Token처럼 쓸 수 없다. 권한 목록은 임의 JWT authority 문자열 대신 검증된 Role에 대한 서버의 `TokenRole` 매핑으로 결정한다.

## 인가 정책

Role의 `hasRole("USER")`는 `ROLE_USER`를 의미한다. Role만 있거나 Authority만 있으면 거부한다. ADMIN에 USER 권한을 자동 상속시키지 않는다. URL 정책은 `SecurityConfig`, 객체 소유자 정책은 실제 컨트롤러의 `@PreAuthorize`에 있다.

| 메서드/엔드포인트 | 요구 권한 및 범위 |
| --- | --- |
| POST `/users/register`, `/users/check-id`, 두 로그인, `/auth/refresh` | 익명 허용 |
| GET `/api/school/search`, `/api/school/search/openapi` | 익명 허용 |
| GET `/users/ranking`, `/users/lives`, `/api/device/logs/{userId}`, `/api/sse/lives/{userId}` | USER + `user:read`; 개인 데이터는 본인만 |
| POST `/users/lives/consume`, `/users/session/start`, `/api/school/verify` | USER + `user:write`; 하트/세션은 본인만 |
| POST `/game/submit`, `/game/record` | USER + `game:play` + 본인 |
| GET `/api/admin/schools`, `/api/admin/{adminId}/info`, `/api/admin/notifications` | ADMIN + `admin:read` + 본인 관리자 ID |
| POST `/api/admin/change-password`, PUT `/api/admin/{adminId}/info` | ADMIN + `admin:write` + 본인 관리자 ID |
| GET `/api/devices/{deviceId}/status`, `/api/device-logs/{deviceId}` | ADMIN + `device:read` |
| POST `/api/devices/{deviceId}/capacity`, `/api/devices/reset-load`, `/api/device-logs`, `/api/device/input` | ADMIN + `device:write`; 작업자 ID가 있는 요청은 본인 관리자 ID |
| GET 등록된 `/api/open/v1` 학교·통계·사용자 조회 | USER 또는 ADMIN + `open:read`; 사용자별 조회는 USER 본인만 |
| POST `/auth/logout` | 인증된 JWT |
| POST `/api/open/v1/users/{userId}/reward` | 전면 거부: 요청자가 임의 포인트를 발행하던 경로 |
| `/users/verify-phone`, `/users/check-student`, 미등록 URL/메서드 | 기본 거부 |

기존 자동 Open API 포인트 지급도 제거했다. 서버가 검증한 비즈니스 이벤트로 보상을 설계하기 전에는 임의 요청으로 지급하지 않는다. 실제 인증 없이 성공을 반환하던 휴대폰/학생 확인 경로도 개방하지 않는다. Swagger UI/스키마 역시 기본 거부다. 필요하면 운영 정책에 맞는 별도 관리자 전용 경로를 명시적으로 추가한다.

기기 입력은 관리자 작업으로 정의했다. 무인 기기의 별도 인증이 필요하면 기기 계정/전용 Authority를 설계해야 한다. 관리자 기기 권한은 현재 전역 범위이고, 지역 격리가 필요하면 추가 객체 인가가 필요하다. 학교 통계/랭킹은 인증된 사용자에게 공개하는 정책이다.

## 정확한 필터 순서와 SecurityContext

Spring Boot 3.4.5의 이 구성에서 실제 체인을 테스트로 검증한다. 바깥쪽에는 서블릿의 `DelegatingFilterProxy`와 Spring Security의 `FilterChainProxy`가 있다. 아래는 선택된 `SecurityFilterChain` 내부의 순서다.

1. `DisableEncodeUrlFilter`
2. `WebAsyncManagerIntegrationFilter`
3. `SecurityContextHolderFilter`
4. `HeaderWriterFilter`
5. `CorsFilter`
6. **`JwtExceptionFilter`**
7. **`JwtAuthenticationFilter`**
8. `SecurityContextHolderAwareRequestFilter`
9. `AnonymousAuthenticationFilter`
10. `SessionManagementFilter`
11. `ExceptionTranslationFilter`
12. `AuthorizationFilter`
13. `DispatcherServlet` → 메서드 인가 → 컨트롤러

커스텀 필터는 체인 구성 시 직접 생성한다. `@Component` 필터의 자동 서블릿 등록으로 이중 실행되지 않게 한다. `addFilterBefore`에서 기준으로 삼은 `UsernamePasswordAuthenticationFilter`는 form login을 끄므로 실제 체인에는 없다.

`SecurityContextHolderFilter`가 context를 준비한다. JWT 필터는 암호학적 검증과 Redis 폐기 확인 후에만 인증 완료 `UsernamePasswordAuthenticationToken`을 만든다. principal은 검증된 subject이고 credentials는 null이다. 새 `SecurityContext`에 Authentication을 저장하고 기본 ThreadLocal 전략의 `SecurityContextHolder`에 바인딩한다. 같은 요청의 URL 인가, 메서드 인가, 컨트롤러에서 이를 참조한다.

`STATELESS`와 `NullSecurityContextRepository` 때문에 HttpSession에 저장하지 않는다. 다음 요청은 JWT와 Redis를 다시 검증한다. 외곽 `SecurityContextHolderFilter`의 finally가 ThreadLocal을 정리하므로 풀에서 재사용되는 스레드에 이전 사용자가 남지 않는다. 테스트는 요청 완료 후 Authentication이 비어 있고 세션도 생성되지 않았음을 검증한다.

`WebAsyncManagerIntegrationFilter`는 Spring MVC Callable의 context 전파를 지원한다. 임의 Executor에 ThreadLocal이 저절로 전달되는 것은 아니다. ERROR/ASYNC 재디스패치는 최초 REQUEST의 인증을 전제로 허용한다. SSE 구독의 소유자 검사는 최초 연결에서 수행하며 이미 열린 스트림을 로그아웃 시 강제 종료하는 기능은 이 구현에 없다.

## 예외 처리

`ExceptionTranslationFilter`는 자신의 뒤에서 발생한 인증/인가 예외를 처리하므로 앞선 JWT 파싱 예외를 잡을 수 없다. 앞에 배치한 `JwtExceptionFilter`가 `chain.doFilter`를 감싸고 `ExpiredJwtException`과 `JwtException`(SignatureException 등 포함)을 잡아 ObjectMapper로 JSON을 쓴다.

- 무토큰 보호 요청/잘못된 로그인: 401 `UNAUTHENTICATED`
- 만료: 401 `TOKEN_EXPIRED`
- 서명/형식/유형/폐기/재사용 오류: 401 `INVALID_TOKEN`
- 권한 또는 소유자 불일치: 403 `ACCESS_DENIED`
- Redis 등 저장소 접근 실패: 503 `AUTH_STORE_UNAVAILABLE`; 인증을 우회하지 않는다.

공통 응답은 `status`, `code`, `path`, `timestamp`이고 내부 예외 메시지나 토큰은 노출하지 않는다. 401에는 `WWW-Authenticate: Bearer`가 있다. 인증 진입점/AccessDeniedHandler와 컨트롤러에서 발생하는 로그인·재발급 예외도 같은 writer를 쓴다. CORS 거부나 잘못된 요청 JSON 같은 비인증 프로토콜 오류는 해당 프레임워크 처리 경로를 따른다.

## Redis RTR와 로그아웃

- `auth:{sid}:refresh`에는 토큰 원문 대신 SHA-256 해시를 보관한다. 충분한 엔트로피를 가진 서명 토큰의 대조 용도이므로 비밀번호와 달리 느린 해시가 필요하지 않다.
- 기본 세션 수명은 7일, Access Token 수명은 최대 15분이다. Access 만료는 세션 절대 만료를 넘지 않는다. 회전으로 세션을 무한 연장하지 않는다.
- Lua가 기존 해시 비교와 교체를 한 번에 처리한다. `SET ... KEEPTTL`로 기존 절대 만료를 유지한다. 두 요청이 동시에 같은 Refresh Token으로 교체할 수 없다.
- 일치하지 않는 이전 토큰이 재사용되면 `revoked`를 설정하고 refresh 상태를 삭제한다. 현재 세션의 Access/Refresh Token 전체를 거부한다. 같은 계정의 다른 로그인 세션은 별개다.
- 동시 요청에서는 하나만 200을 받지만, 뒤의 재사용 탐지가 승자의 세션까지 폐기할 수 있다. 의도적인 엄격한 탐지 정책이다. 클라이언트는 refresh를 single-flight로 직렬화하고, 성공 응답 유실 후 예전 토큰으로 무조건 재시도하지 않는다. 이 경우 재로그인이 필요하다.
- 로그아웃 Lua는 현재 `jti`의 블랙리스트를 남은 Access 유효시간만큼 저장하고, 세션 폐기 및 refresh 삭제도 원자 처리한다. 반복/경합 로그아웃으로 기존 폐기 TTL을 줄이지 않는다.
- 모든 키에 같은 `{sid}` 해시 태그를 써 Redis Cluster의 동일 슬롯 제약을 지킨다.
- Access 검증 때 refresh 세션의 존재와 폐기/블랙리스트를 확인한다. Redis 장애는 503, 상태 유실/eviction은 401로 닫힌다. Redis 유실로 차단 토큰이 다시 유효해지는 경로를 막는다.
- 이미 인증 단계를 지난 동시 요청의 비즈니스 트랜잭션까지 되돌리지는 않는다. 로그아웃 완료 이후 시작한 검증부터 차단을 보장한다.

따라서 무상태라는 말은 **서블릿 인증 세션을 유지하지 않는다**는 뜻이다. 즉시 폐기/RTR 때문에 Redis 상태와 요청당 네트워크 비용이 존재한다. Redis 가용성이 인증 가용성에 직접 영향을 준다.

## 실행과 배포 전제

JDK 17과 Redis 6 이상(`KEEPTTL` 지원)이 필요하다. 테스트는 `redis-server` 실행 파일을 PATH에서 찾으며 `REDIS_SERVER`로 절대 경로를 지정할 수도 있다. 임시 포트의 실제 프로세스를 시작하고 종료하며 운영 Redis를 flush하지 않는다. JPA 컨텍스트는 테스트용 H2를 사용하고, 계정/하트 일부 저장소 및 서비스는 mock이다. JWT·Security 전체 필터 체인·Redis 저장소·Lua는 실제 구현이다. MariaDB 호환성이나 Redis Cluster/장애조치 자체를 검증하는 테스트는 아니다.

```sh
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
./mvnw clean test
```

첫 빌드에는 clean이 필요하다. 소스에서 삭제한 인터셉터의 이전 class가 target에 남으면 컴포넌트 스캔에 재등장할 수 있다.

운영 환경 변수:

- `JWT_SECRET`: 최소 32 랜덤 바이트의 Base64. 기본값 없이 누락 시 기동 실패. 예: `openssl rand -base64 32`. 테스트 전용 0바이트 키를 운영에 쓰지 않는다.
- `NEIS_API_KEY`: 학교 조회 API 키. 미설정 시 외부 학교 조회를 거부한다. 이전 소스에 포함되었던 키는 발급처에서 폐기·재발급해야 한다.
- `DB_PASSWORD`, `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`, `REDIS_SSL`
- `CORS_ALLOWED_ORIGINS`: 허용 웹 앱 origin을 쉼표로 지정. 기본은 cross-origin 허용 없음. 쿠키 인증과 credentials를 사용하지 않는다.

TLS는 프록시/인그레스에서 강제하고, 로그인·재발급의 rate limit과 인증 실패 관측은 운영 계층에 설정한다. Redis는 인증, TLS, 접근 격리, 적절한 persistence 및 noeviction 정책을 적용한다. 이 구현은 단일 HMAC 키이므로 키 교체 시 모든 기존 토큰이 무효화된다. 무중단 키 순환이 필요하면 kid와 검증 키 집합 또는 비대칭 서명을 추가한다.

기존 관리자 비밀번호는 평문이므로 **배포 전 BCrypt 해시로 마이그레이션하거나 비밀번호를 재설정해야 한다**. 평문 fallback은 제공하지 않는다. 사용자 비밀번호는 기존 BCrypt 저장 정책을 유지하며 관리자 변경 비밀번호도 BCrypt로 저장한다. 비밀번호 해시는 엔티티 JSON 직렬화에서 제외했다. 현재 계정 삭제는 refresh에서 확인하며 기존 Access Token의 최대 15분 수명까지 즉시 계정 삭제를 반영하지는 않는다. 비밀번호 변경 시 모든 기기 세션 폐기가 필요하다면 사용자별 세션 인덱스/보안 버전 검증을 추가해야 한다.

CSRF 비활성화는 브라우저가 자동 첨부하는 인증 쿠키를 사용하지 않는 현재 계약을 전제로 한다. Refresh Token을 HttpOnly 쿠키로 바꾸면 CSRF/Origin 정책도 함께 재설계해야 한다. 클라이언트는 토큰을 OS 보안 저장소 등 적절한 저장소에 보관하고 로그에 출력하지 않는다.

## 면접 압박 질문 3개

### 1. “JWT라서 무상태라면서 Redis도 쓰고 SecurityContext도 저장하나요? 스레드가 재사용되면 인증이 샙니까?”

무상태는 HttpSession에 로그인 상태를 보관하지 않는다는 뜻입니다. 검증된 Authentication은 한 요청 동안 ThreadLocal SecurityContext에만 존재하고 외곽 SecurityContextHolderFilter가 finally에서 제거합니다. 다음 요청은 JWT와 Redis 폐기 상태를 다시 확인합니다. Redis는 RTR과 즉시 폐기를 위한 보안 상태이므로 완전히 상태 없는 시스템이라고 말하지 않습니다. 그 대가로 요청당 Redis 비용과 가용성 의존성이 생기며, 장애 시에는 인증을 열어두는 대신 503을 반환합니다. 임의 비동기 작업은 별도의 context 전파가 필요합니다.

### 2. “ExceptionTranslationFilter가 있는데 왜 JwtExceptionFilter를 만들죠? 401과 403은 어떻게 다릅니까?”

필터의 catch는 자기 뒤에서 실행한 체인의 예외만 볼 수 있습니다. JWT 필터는 ExceptionTranslationFilter보다 앞에 있으므로 그 파싱 오류는 기본 예외 번역 범위 밖입니다. JwtExceptionFilter를 JWT 필터 바로 앞에 두어 만료와 서명 오류를 JSON 401로 변환합니다. URL/메서드 인가의 경우 익명 요청은 AuthenticationEntryPoint의 401, 인증된 사용자에게 역할·권한·소유권이 부족하면 AccessDeniedHandler의 403입니다. 허용 URL도 필터 자체를 건너뛰는 것이 아니므로 잘못된 Bearer 토큰을 보내면 거부됩니다.

### 3. “동일 Refresh Token 요청이 두 서버에 동시에 도착하면 둘 다 재발급되지 않나요? 로그아웃한 JWT는 여전히 서명이 유효한데요?”

Java의 GET-비교-SET은 경쟁하므로 Lua에서 기존 토큰 해시 대조와 교체를 원자 실행합니다. 한 요청만 교체에 성공하고 재사용 요청은 세션 패밀리를 폐기합니다. 엄격한 정책상 정상 중복 요청도 재로그인이 필요할 수 있어 클라이언트는 single-flight 처리를 해야 합니다. 로그아웃은 현재 Access jti 블랙리스트, 세션 폐기, Refresh 삭제를 같은 슬롯의 Lua에서 처리합니다. Access 필터는 서명뿐 아니라 이 상태도 확인합니다. TTL은 토큰의 남은 수명과 절대 세션 기한을 기준으로 하며 Access가 세션보다 오래 남지 않습니다. 이미 인증을 마친 진행 중 요청을 소급 취소하는 보장은 별도 트랜잭션 정책 없이는 하지 않습니다.

## 검증 결과

전체 49개 통과: 인가 슬라이스 31개, JWT/실제 Redis 통합 14개, 기존 테스트 4개. 실패/스킵 0개.

- `AuthorizationSliceTest`: 실제 User/Admin 컨트롤러의 허용·거부·소유자 검사, 나머지 보호 경로의 URL 정책, Redis 장애 503.
- `JwtIntegrationTest`: 실제 사용자/관리자 로그인 JWT, 필터 순서, 무세션/context 정리, 파싱 오류, RTR 재사용·HTTP 동시 요청, TTL 경계, 로그아웃, 세션 유실, 실제 컨트롤러 소유권, CORS.

## 근거 문서

- [Spring Security Servlet Architecture](https://docs.spring.io/spring-security/reference/servlet/architecture.html): 필터 체인, 상대적 필터 위치, 예외 번역 범위.
- [Spring Security Authentication Architecture](https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html): Authentication과 SecurityContextHolder.
- [Redis Lua scripting](https://redis.io/docs/latest/develop/programmability/eval-intro/): Lua 스크립트의 원자 실행.
