## AWS Route Finder (GoLang Ver)
AWS Route Finder는 VPC Reachability Analyzer를 기반으로 AWS 인프라의 경로 상의 연결성을 손쉽게 테스트할 수 있는 도구입니다.
이 도구를 사용하여 AWS 네트워크 경로를 분석하고, 인스턴스와 인터넷 게이트웨이 간의 연결성을 확인할 수 있습니다.

기능
EC2 인스턴스 등록: 현재 AWS 계정의 모든 EC2 인스턴스를 등록합니다.
인터넷 게이트웨이 등록: 현재 AWS 계정의 모든 인터넷 게이트웨이를 등록합니다.
경로 분석 생성: 지정된 소스 및 대상 간의 네트워크 경로 분석을 생성합니다.
경로 분석 실행: 생성된 네트워크 경로 분석을 실행하고 결과를 반환합니다.
실시간 경로 분석 결과 확인: 경로 분석 결과를 기반으로 네트워크 연결성을 검증합니다.

## 설치

```bash
git clone https://github.com/Shephexd/aws-route-finder-go
alias arf="go run $PWD/main.go"
arf
```

## 실행
```bash
go run main.go run SOURCE TARGET
```

### examples

```bash
go run main.go run 10.x.x.x 192.x.x.x --protocol udp --port 8000
go run main.go run i-123123412 i-1233258767 --protocol tcp --port 8000
go run main.go run eni-123123412 i-1233258767 --protocol udp --port 8000
go run main.go run eni-123123412 www.example.com --protocol udp --port 8000
```


## Interfaces
#### Source Types
- InstanceID
- Network Interface ID
- IP Address on AWS(Private or Public)

#### Target Types
- InstanceID
- Network Interface ID
- IP Address Anywhere
- FQDN (DNS lookup required)

#### Flags
- protocol: tcp/udp (default: tcp)
- port: 0 - 65535 (default: 0 All)
- region: AWS Region (default: CURRENT_REGION)
