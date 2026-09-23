#!/usr/bin/env ruby
require "json" # 합성 AWS 입력을 파싱합니다.
require "time" # 원본 발생 시각을 비교합니다.
module LogStash # 실제 런타임 대신 변환 함수만 검증하는 최소 shim입니다.
  class Timestamp # 필터에 필요한 시간 인터페이스만 제공합니다.
    attr_reader :time # 비교할 Ruby Time을 노출합니다.
    def initialize(value) # 시각을 받아 객체로 감쌉니다.
      @time = value # 원래 시간 값을 보존합니다.
    end # 생성자를 마칩니다.
    def self.now # 수집 시각 생성 함수를 제공합니다.
      new(Time.now.utc) # 현재 UTC 시각입니다.
    end # now 함수를 마칩니다.
  end # Timestamp shim을 마칩니다.
  class Event # 실제 Logstash Event와 별개인 테스트용 인터페이스입니다.
    def initialize(values = {}) # 입력 필드를 받습니다.
      @values = Marshal.load(Marshal.dump(values)) # 다른 이벤트와 상태를 공유하지 않습니다.
      @values["@timestamp"] ||= Timestamp.now # 기본 수집 시각을 넣습니다.
    end # 생성자를 마칩니다.
    def keys(path) # Logstash 중첩 경로를 분해합니다.
      path.start_with?("[") ? path.scan(/\[([^\]]+)\]/).flatten : [path] # [a][b]와 일반 루트 이름을 지원합니다.
    end # 경로 처리를 마칩니다.
    def get(path) # 필드 읽기를 제공합니다.
      keys(path).reduce(@values) { |value, key| value.is_a?(Hash) ? value[key] : nil } # 없는 필드는 nil입니다.
    end # 읽기를 마칩니다.
    def set(path, value) # 필드 쓰기를 제공합니다.
      parts = keys(path) # 경로를 나눕니다.
      last = parts.pop # 마지막 필드 이름을 분리합니다.
      parent = parts.reduce(@values) { |memo, key| memo[key] ||= {} } # 필요한 중첩 부모를 만듭니다.
      parent[last] = value # 값을 저장합니다.
    end # 쓰기를 마칩니다.
    def remove(path) # 제어 필드 제거를 지원합니다.
      parts = keys(path) # 경로를 나눕니다.
      last = parts.pop # 제거할 키입니다.
      parent = parts.reduce(@values) { |memo, key| memo.is_a?(Hash) ? memo[key] : nil } # 부모 경로를 찾습니다.
      parent.delete(last) if parent.is_a?(Hash) # 존재하는 필드만 제거합니다.
    end # 제거를 마칩니다.
    def tag(value) # 실패 태그를 추가합니다.
      @values["tags"] ||= [] # 태그 배열을 만듭니다.
      @values["tags"] << value unless @values["tags"].include?(value) # 같은 태그를 중복하지 않습니다.
    end # 태그를 마칩니다.
    def clone # 독립 이벤트 복사를 지원합니다.
      Event.new(@values) # 생성자의 깊은 복사를 사용합니다.
    end # 복사를 마칩니다.
  end # Event shim을 마칩니다.
end # LogStash namespace를 마칩니다.
class EmbeddedTest # Ruby 필터의 내장 테스트 DSL을 기록합니다.
  attr_reader :event_builder, :expectations # 실행할 입력과 조건을 노출합니다.
  def initialize # 테스트 상태를 초기화합니다.
    @expectations = [] # 검사할 블록을 담습니다.
  end # 초기화를 마칩니다.
  def in_event(&block) # 내장 테스트 입력을 등록합니다.
    @event_builder = block # 실행 시 새 이벤트를 만들 블록입니다.
  end # 입력 등록을 마칩니다.
  def expect(name, &block) # 내장 테스트 조건을 등록합니다.
    @expectations << [name, block] # 이름과 검사 블록을 보관합니다.
  end # 조건 등록을 마칩니다.
end # DSL shim을 마칩니다.
EMBEDDED = [] # 실제 필터가 등록하는 테스트 목록입니다.
def test(name, &block) # normalize.rb의 test 선언을 지원합니다.
  item = EmbeddedTest.new # 독립 테스트 상태입니다.
  item.instance_eval(&block) # 입력과 검사 블록을 등록합니다.
  EMBEDDED << [name, item] # 나중에 실행할 목록에 넣습니다.
end # 내장 테스트 등록을 마칩니다.
def assert_case(name) # 실패를 프로세스 오류로 반환합니다.
  raise "FAIL: #{name}" unless yield # false 조건을 성공으로 숨기지 않습니다.
  puts "PASS: #{name}" # 검사 이름만 출력합니다.
end # assertion을 마칩니다.
ROOT = File.expand_path("..", __dir__) # 프로젝트 루트를 찾습니다.
load File.join(ROOT, "runtime", "normalize.rb") # 복제 구현 대신 실제 배포할 필터를 불러옵니다.
register({}) # 필터의 허용 소스 목록을 초기화합니다.
def fixture(name) # 제공된 합성 샘플을 읽습니다.
  JSON.parse(File.read(File.join(ROOT, "samples", name), encoding: "UTF-8")) # 단일 JSON 또는 한 줄 JSONL을 파싱합니다.
end # 샘플 읽기를 마칩니다.
def input_event(source, payload, object_id = "stable-s3-object-offset") # Filebeat 출력 경계의 이벤트를 모사합니다.
  raw = payload.is_a?(String) ? payload : JSON.generate(payload) # message에 원문 문자열을 넣습니다.
  LogStash::Event.new({"message" => raw, "fields" => {"source_kind" => source, "collection_region" => "ap-northeast-2"}, "@metadata" => {"_id" => object_id}, "aws" => {"s3" => {"object" => {"key" => "test-prefix/example.json.gz"}}}}) # 소스·리전·객체 ID·S3 위치를 보존합니다.
end # 입력 생성을 마칩니다.
EMBEDDED.each do |name, item| # 실제 필터에 포함된 내장 테스트도 실행합니다.
  events = filter(LogStash::Event.new(item.event_builder.call)) # 실제 filter에 새 입력을 넣습니다.
  item.expectations.each { |label, block| assert_case("내장: #{name} / #{label}") { block.call(events) } } # 선언한 모든 조건을 검사합니다.
end # 내장 테스트 실행을 마칩니다.
trail = fixture("cloudtrail.json").fetch("Records") # Filebeat가 할 Records 배열 전개를 경계 테스트에서 모사합니다.
trail_events = trail.each_with_index.flat_map { |record, index| filter(input_event("cloudtrail", record, "cloudtrail-object-#{index}")) } # 개별 JSON message를 넣습니다.
assert_case("CloudTrail 개수·ID·원본 시각") { trail_events.length == trail.length && trail_events.first.get("[event][id]") == trail.first["eventID"] && trail_events.first.get("@timestamp").time == Time.iso8601(trail.first["eventTime"]) } # 이벤트 손실과 시간 변형을 검사합니다.
assert_case("CloudTrail 계정·리전·S3 위치") { trail_events.first.get("[cloud][account][id]") == "123456789012" && trail_events.first.get("[cloud][region]") == "ap-northeast-2" && trail_events.first.get("[aws][s3][object][key]") == "test-prefix/example.json.gz" } # 연관 분석과 원본 재처리 정보를 확인합니다.
cwl = fixture("cloudwatch.json") # CloudWatch envelope 샘플입니다.
cwl["logEvents"] << cwl["logEvents"].first.merge("id" => "cw-second", "timestamp" => cwl["logEvents"].first["timestamp"] + 1500, "message" => "second event") # 한 envelope에 두 이벤트를 만듭니다.
cwl_first = filter(input_event("cloudwatch", cwl)) # 첫 수신을 처리합니다.
cwl_again = filter(input_event("cloudwatch", cwl)) # 동일 객체를 재수신합니다.
assert_case("CloudWatch 배열 분리·고유 ID·재처리 동일 ID") { cwl_first.length == 2 && cwl_first.map { |e| e.get("[@metadata][document_id]") }.uniq.length == 2 && cwl_first.map { |e| e.get("[@metadata][document_id]") } == cwl_again.map { |e| e.get("[@metadata][document_id]") } } # 형제 덮어쓰기와 재시도 중복을 검사합니다.
assert_case("CloudWatch 날짜 인덱스·그룹·수집 리전") { cwl_first.first.get("[@metadata][target_index]") == "whs-elk-elasticsearch-logs-cloudwatch-2026.09.16" && cwl_first.first.get("[aws][cloudwatch][log_group]") == cwl["logGroup"] && cwl_first.first.get("[cloud][region]") == "ap-northeast-2" } # 소스 메타데이터와 공통 이름 규칙을 확인합니다.
assert_case("CloudWatch 밀리초 정밀도") { (cwl_first.last.get("@timestamp").time - cwl_first.first.get("@timestamp").time - 1.5).abs < 0.000001 } # 초 단위 반올림을 검사합니다.
waf = fixture("waf.json") # WAF 내부 JSON을 가진 envelope입니다.
waf_events = filter(input_event("waf", waf)) # 실제 필터를 실행합니다.
waf_payload = JSON.parse(waf["logEvents"].first["message"]) # 원문에서 기대 값을 읽습니다.
assert_case("WAF 내부 action·URI 추출") { waf_events.length == 1 && waf_events.first.get("[event][action]") == waf_payload["action"] && waf_events.first.get("[url][path]") == waf_payload.dig("httpRequest", "uri") } # envelope와 개별 요청을 구분하는지 검사합니다.
mixed = Marshal.load(Marshal.dump(waf)) # 샘플을 독립 복사합니다.
mixed["logEvents"] << {"id" => "waf-broken", "timestamp" => 1789516800000, "message" => "not JSON"} # 같은 envelope에 깨진 항목을 추가합니다.
mixed_events = filter(input_event("waf", mixed)) # 정상과 오류를 함께 처리합니다.
assert_case("정상 WAF와 오류 형제를 각각 보존") { mixed_events.length == 2 && mixed_events.map { |e| e.get("[event][dataset]") }.sort == ["aws.quarantine", "aws.waf"] && mixed_events.last.get("[error][item_position]") == 1 } # 한 실패가 정상 로그를 버리지 않는지 확인합니다.
finding = fixture("guardduty.json") # GuardDuty Finding 샘플입니다.
original_finding = filter(input_event("guardduty", finding)).first # 첫 버전을 처리합니다.
finding["updatedAt"] = "2026-09-16T01:00:00Z" # 동일 ID의 갱신 버전을 만듭니다.
updated_finding = filter(input_event("guardduty", finding)).first # 새 버전을 처리합니다.
assert_case("GuardDuty 갱신 버전·심각도 보존") { original_finding.get("[aws][guardduty][finding_id]") == updated_finding.get("[aws][guardduty][finding_id]") && original_finding.get("[@metadata][document_id]") != updated_finding.get("[@metadata][document_id]") && updated_finding.get("[event][severity]") == finding["severity"] } # 같은 탐지의 갱신 이력이 남는지 확인합니다.
malformed = File.read(File.join(ROOT, "samples", "malformed.json.txt"), encoding: "UTF-8") # 의도적으로 깨진 원문입니다.
failed = filter(input_event("cloudwatch", malformed)) # 파싱 실패를 유도합니다.
assert_case("깨진 JSON 원문 격리") { failed.length == 1 && failed.first.get("[event][dataset]") == "aws.quarantine" && failed.first.get("[event][original]") == malformed && failed.first.get("[@metadata][target_index]").match?(/\Awhs-elk-elasticsearch-logs-quarantine-\d{4}\.\d{2}\.\d{2}\z/) } # 원문 보존과 격리 인덱스의 공통 이름 규칙을 확인합니다.
control = filter(input_event("cloudwatch", fixture("cloudwatch-control.json"))) # 제어 메시지 샘플을 처리합니다.
assert_case("control envelope는 업무 이벤트가 아닌 격리 보관") { control.length == 1 && control.first.get("[event][dataset]") == "aws.quarantine" } # 업무 이벤트를 가짜로 만들지 않는지 확인합니다.
invalid_time = trail.first.merge("eventTime" => "invalid-time") # 잘못된 이벤트 시간을 만듭니다.
assert_case("잘못된 발생 시각 격리") { filter(input_event("cloudtrail", invalid_time)).first.get("[event][dataset]") == "aws.quarantine" } # 잘못된 시간을 현재 시각으로 숨기지 않는지 확인합니다.
puts "정규화 함수 검증 완료. 실제 Filebeat·Logstash·Elasticsearch·AWS 통합 검증이 아닙니다." # 테스트의 실질 범위를 명확히 표시합니다.
