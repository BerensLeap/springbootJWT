# JWT 인증 기반 Spring Boot REST API 프로젝트

## 📌 개요

이 프로젝트는 **JWT(JSON Web Token)**를 활용한 인증(Authentication) 및 인가(Authorization) 시스템을 구현한 Spring Boot 기반의 RESTful API 서버입니다. 사용자는 회원가입 및 로그인을 통해 JWT를 발급받아 보호된 리소스에 접근할 수 있습니다. 특히 관리자는 특정 사용자에게 관리자 권한을 부여할 수 있는 기능을 제공하며, API 문서화 도구인 Swagger UI를 통해 모든 API 엔드포인트를 편리하게 테스트할 수 있습니다.

또한, GitHub Actions를 활용한 CI/CD 파이프라인을 구축하여 코드 변경 사항이 발생할 때마다 자동으로 빌드, 테스트, 그리고 AWS EC2 인스턴스로의 배포가 이루어지도록 설정했습니다. Redis를 활용하여 JWT 리프레시 토큰 관리 및 효율적인 캐싱을 구현했습니다.

---

## 🔎 배포 (GitHub Actions + EC2 + Redis)

-GitHub Actions를 사용하여 코드 푸시 시 자동 빌드, 테스트 및 배포를 수행합니다.

-빌드된 JAR 파일은 AWS EC2 인스턴스로 배포됩니다.

-Redis는 JWT 리프레시 토큰 관리 및 캐싱을 위해 사용됩니다. (Redis 배포 방식은 추가 논의 필요, 예를 들어 EC2에 직접 설치 또는 AWS ElastiCache 사용)

---

## 📮 API 명세

| 메서드 | URL | 설명 | 권한 |
|------|------|------|------|
| POST | /signup | 회원가입 | - |
| POST | /login | 로그인 및 토큰 발급 | - |
| PATCH | /admin/users/{userId}/roles | 특정 사용자에게 관리자 권한 부여 | 관리자(ADMIN) |

---

## 🧾 테스트

-JUnit 5와 MockMvc, Mockito를 기반으로 단위 및 통합 테스트를 제공합니다.

-GitHub Actions 워크플로우에 테스트 자동 수행 단계가 포함되어, 배포 전 코드의 안정성을 검증합니다.

-테스트 실행 명령어: ./gradlew test

---

📂 배포 정보 

-EC2 서버 주소: http://15.164.94.214:8080

-Swagger UI 주소: :http://15.164.94.214:8080/swagger-ui/index.html

---

🛠 기술 스택

- **백엔드 프레임워크: Spring Boot 3.x**

- **보안: Spring Security + JWT**

- **데이터베이스: (프로젝트에 사용된 DB 명시, 예: H2 (개발), MySQL, PostgreSQL 등)**

- **캐싱/토큰 관리: Redis**

- **테스트: JUnit 5, Mockito**

- **API 문서화: Swagger (springdoc-openapi)**

- **CI/CD: GitHub Actions**

- **클라우드 플랫폼: AWS EC2**

- **빌드 도구: Gradle**

