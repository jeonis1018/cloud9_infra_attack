require "json" # AWS 로그의 JSON 문자열을 파싱합니다.
require "digest" # 안정적인 문서 ID를 SHA-256으로 만듭니다.
require "time" # AWS의 ISO8601 시간을 UTC로 변환합니다.
def register(params) # Logstash가 파이프라인 시작 때 호출하는 초기화 함수입니다.
  @allowed = %w[cloudtrail cloudwatch waf guardduty].freeze # 소스 이름을 허용 목록으로 제한합니다.
end # 초기화 함수가 끝납니다.
def stamp(value) # AWS가 주는 문자열 또는 epoch milliseconds를 해석합니다.
  return Time.at(value.to_f / 1000.0).utc if value.is_a?(Numeric) # 숫자 시간은 밀리초로 처리합니다.
  Time.iso8601(value.to_s).utc # ISO8601 문자열을 명시적으로 검증하고 UTC로 바꿉니다.
end # 시간 변환 함수가 끝납니다.
def quarantine(event, error) # 파싱할 수 없는 이벤트도 원본을 포함해 별도로 저장합니다.
  result = event.clone # 입력 이벤트를 변형하지 않고 복사합니다.
  raw = event.get("message").to_s # Filebeat가 읽은 원본 문자열을 확보합니다.
  result.set("[event][original]", raw) # 원본을 재처리 가능한 필드에 보관합니다.
  result.set("[event][dataset]", "aws.quarantine") # 정상 이벤트와 구분합니다.
  result.set("[error][message]", "#{error.class}: #{error.message}") # 실패 종류와 이유를 보관합니다.
  result.tag("_parsefailure") # Kibana에서 오류를 바로 찾을 태그입니다.
  result.set("[@metadata][target_index]", "whs-elk-elasticsearch-logs-quarantine-#{Time.now.utc.strftime('%Y.%m.%d')}") # 오류는 공통 이름 규칙과 처리 날짜로 보관합니다.
  base = event.get("[@metadata][_id]") || Digest::SHA256.hexdigest(raw) # Filebeat의 원본 객체 ID를 우선 사용합니다.
  result.set("[@metadata][document_id]", Digest::SHA256.hexdigest("quarantine|#{base}|#{raw}")) # 같은 실패 재전송을 멱등하게 처리합니다.
  result # 격리된 이벤트를 반환합니다.
end # 오류 격리 함수가 끝납니다.
def normalize(event, source, payload, wrapper, item, position) # 개별 로그를 ECS와 서비스 필드로 변환합니다.
  result = event.clone # Filebeat의 S3 객체 위치와 metadata를 유지합니다.
  result.set("[event][ingested]", LogStash::Timestamp.now) # 플랫폼 수집 시각을 별도로 남깁니다.
  result.set("[event][dataset]", "aws.#{source}") # Kibana에서 서비스별로 나눌 필드입니다.
  result.set("[cloud][provider]", "aws") # 클라우드 공급자를 기록합니다.
  result.set("[aws][payload]", payload) # 삭제하지 않은 서비스 원문을 보존합니다.
  original = item ? item.fetch("message") : event.get("message").to_s # 배열 분리 후에는 개별 원문을 선택합니다.
  result.set("[event][original]", original) # 필드 변환 전의 이벤트 문자열입니다.
  result.set("message", original) # 일반 로그 조회 화면의 메시지입니다.
  account = wrapper && wrapper["owner"] # CloudWatch envelope의 계정 정보를 보존합니다.
  region = nil # 소스에 지역 정보가 있을 때 채웁니다.
  identity = item && item["id"] # CloudWatch logEvents의 고유 ID를 가져옵니다.
  time_value = item && item["timestamp"] # CloudWatch의 원본 이벤트 발생 시간을 가져옵니다.
  if wrapper # CloudWatch envelope가 있는 소스에 적용합니다.
    result.set("[aws][cloudwatch][log_group]", wrapper["logGroup"]) # 로그 그룹을 보관합니다.
    result.set("[aws][cloudwatch][log_stream]", wrapper["logStream"]) # 로그 스트림을 보관합니다.
    result.set("[aws][cloudwatch][owner]", wrapper["owner"]) # envelope의 소유 계정을 남깁니다.
    result.set("[aws][cloudwatch][message_type]", wrapper["messageType"]) # 원래 메시지 유형을 남깁니다.
  end # envelope 메타데이터 설정을 마칩니다.
  case source # 서비스에 맞게 중요한 필드를 꺼냅니다.
  when "cloudtrail" # CloudTrail API 활동입니다.
    identity = payload.fetch("eventID") # API 이벤트의 고유 ID가 없으면 격리합니다.
    time_value = payload.fetch("eventTime") # API 호출 시간을 사용합니다.
    account = payload["recipientAccountId"] || payload.dig("userIdentity", "accountId") # 대상 계정을 우선 사용합니다.
    region = payload["awsRegion"] # API 호출 리전을 기록합니다.
    result.set("[event][action]", payload["eventName"]) # 실행된 API 이름입니다.
    result.set("[event][provider]", payload["eventSource"]) # API 서비스 이름입니다.
    result.set("[event][outcome]", payload.key?("errorCode") ? "failure" : "success") # 실패 응답 유무를 기록합니다.
    result.set("[source][address]", payload["sourceIPAddress"]) # IP가 아닌 AWS 내부 이름도 보존할 keyword 필드입니다.
    result.set("[user][id]", payload.dig("userIdentity", "arn")) # 호출 주체 ARN입니다.
  when "waf" # WAF 요청 로그입니다.
    time_value = payload.fetch("timestamp") # WAF가 기록한 요청 시각을 우선합니다.
    identity = payload.dig("httpRequest", "requestId") || identity # 요청 ID가 없으면 CloudWatch ID를 사용합니다.
    arn = payload["webaclId"].to_s.split(":") # Web ACL ARN에서 계정과 리전을 추출합니다.
    account = arn[4] if arn.length > 5 # ARN이 정상일 때 계정 정보를 설정합니다.
    region = arn[3] if arn.length > 5 # CloudFront용 ARN의 리전 의미는 AWS 원문대로 남깁니다.
    result.set("[event][action]", payload.fetch("action")) # ALLOW, BLOCK 등의 action입니다.
    result.set("[rule][id]", payload["terminatingRuleId"]) # 최종 판정 규칙 ID입니다.
    result.set("[source][address]", payload.dig("httpRequest", "clientIp")) # 요청한 클라이언트 주소입니다.
    result.set("[url][path]", payload.dig("httpRequest", "uri")) # 요청 URI를 보관합니다.
    result.set("[http][request][method]", payload.dig("httpRequest", "httpMethod")) # GET·POST 등 메서드입니다.
  when "guardduty" # GuardDuty 탐지 결과입니다.
    identity = "#{payload.fetch('id')}|#{payload.fetch('updatedAt')}" # 같은 Finding의 갱신 버전은 구분합니다.
    time_value = payload.fetch("updatedAt") # 탐지 결과가 갱신된 시각을 사용합니다.
    account = payload["accountId"] # 탐지 대상 계정입니다.
    region = payload["region"] # 탐지 리전입니다.
    result.set("[event][action]", payload["type"]) # Finding 유형을 검색할 수 있게 합니다.
    result.set("[event][severity]", payload["severity"]) # GuardDuty의 숫자 심각도를 보존합니다.
    result.set("[aws][guardduty][finding_id]", payload["id"]) # 갱신 버전과 별개로 Finding ID를 남깁니다.
  when "cloudwatch" # 서버·애플리케이션 문자열 로그입니다.
    raise ArgumentError, "CloudWatch envelope가 없습니다." unless item # 원본 발생 시각 없는 잘못된 계약을 격리합니다.
    region = wrapper["logGroup"].to_s.start_with?("arn:") ? wrapper["logGroup"].split(":")[3] : nil # 일반 로그 그룹 이름은 리전을 추측하지 않습니다.
  end # 서비스별 필드 설정을 마칩니다.
  timestamp = stamp(time_value) # 원본 시간이 유효하지 않으면 호출자가 해당 이벤트를 격리합니다.
  result.set("@timestamp", LogStash::Timestamp.new(timestamp)) # 기본 검색 시각을 원본 이벤트 시간으로 바꿉니다.
  result.set("[event][id]", identity.to_s) # 서비스 고유 ID를 조회 필드로 보존합니다.
  result.set("[cloud][account][id]", account.to_s) if account # 존재하는 계정 정보만 기록합니다.
  region ||= event.get("[fields][collection_region]") # 서버 로그에서는 수집 리전이라는 명시적 가정을 사용합니다.
  result.set("[cloud][region]", region.to_s) if region # 리전별 검색에 사용할 필드입니다.
  base = event.get("[@metadata][_id]") || Digest::SHA256.hexdigest(event.get("message").to_s) # S3 객체 위치 기반 ID를 보존합니다.
  result.set("[@metadata][document_id]", Digest::SHA256.hexdigest("#{source}|#{base}|#{identity}|#{position}")) # 배열 항목끼리 덮어쓰지 않는 안정적인 ID를 만듭니다.
  result.set("[@metadata][target_index]", "whs-elk-elasticsearch-logs-#{source}-#{timestamp.strftime('%Y.%m.%d')}") # 같은 원본을 다시 읽어도 같은 날짜 인덱스로 보냅니다.
  result.remove("[fields]") # 입력 제어용 필드는 정규화 후 제거합니다.
  result # 개별 정규화 이벤트를 반환합니다.
end # 정규화 함수가 끝납니다.
def filter(event) # Logstash Ruby 필터의 이벤트 진입점입니다.
  source = event.get("[fields][source_kind]") # Filebeat가 설정한 서비스 이름을 읽습니다.
  raise ArgumentError, "허용하지 않은 source_kind" unless @allowed.include?(source) # 임의 인덱스 이름 생성을 방지합니다.
  payload = JSON.parse(event.get("message").to_s) # 원문 JSON을 파싱합니다.
  raise ArgumentError, "JSON object가 아닙니다." unless payload.is_a?(Hash) # 형식이 맞지 않으면 보관 후 수정하도록 격리합니다.
  if %w[cloudwatch waf].include?(source) # CloudWatch envelope 안의 개별 메시지를 처리합니다.
    items = payload.fetch("logEvents") # DataMessageExtraction=false 계약을 확인합니다.
    raise ArgumentError, "빈 logEvents 또는 control envelope" unless items.is_a?(Array) && !items.empty? # 데이터 없는 control 메시지도 기본 폐기하지 않습니다.
    return items.each_with_index.map do |item, position| # 하나의 envelope를 여러 이벤트로 나눕니다.
      begin # 한 항목의 오류가 정상 형제 이벤트를 가로막지 않게 합니다.
        raise ArgumentError, "logEvents 항목이 object가 아닙니다." unless item.is_a?(Hash) # 항목 타입을 확인합니다.
        value = source == "waf" ? JSON.parse(item.fetch("message")) : {"message" => item.fetch("message")} # WAF는 내부 JSON까지 파싱합니다.
        normalize(event, source, value, payload, item, position) # 공통 필드와 안정적인 문서 ID를 만듭니다.
      rescue StandardError => error # 개별 항목 오류를 잡습니다.
        failed = quarantine(event, error) # 전체 envelope도 보존하여 나중에 재처리할 수 있게 합니다.
        failed.set("[error][item_position]", position) # 실패한 배열 위치를 표시합니다.
        failed.set("[@metadata][document_id]", Digest::SHA256.hexdigest("#{failed.get('[@metadata][document_id]')}|#{position}")) # 여러 실패 항목을 구분합니다.
        failed # 이 항목은 격리 이벤트로 반환합니다.
      end # 개별 항목 처리를 마칩니다.
    end # 분리된 이벤트 배열을 반환합니다.
  end # envelope 처리를 마칩니다.
  [normalize(event, source, payload, nil, nil, 0)] # CloudTrail과 GuardDuty는 이미 개별 JSON입니다.
rescue StandardError => error # JSON 자체가 깨진 경우도 여기에서 처리합니다.
  [quarantine(event, error)] # 파싱 실패가 조용히 버려지지 않도록 합니다.
end # 필터가 끝납니다.
test "CloudWatch 두 항목은 서로 다른 ID이며 밀리초 시간을 보존한다" do # 배열 분리·중복 방지의 회귀 테스트입니다.
  in_event { {"message" => JSON.generate({"owner" => "123456789012", "logGroup" => "app", "logStream" => "one", "logEvents" => [{"id" => "a", "timestamp" => 1700000000000, "message" => "first"}, {"id" => "b", "timestamp" => 1700000001000, "message" => "second"}]}), "fields" => {"source_kind" => "cloudwatch"}, "@metadata" => {"_id" => "same-s3-envelope"}} } # 실제 CloudWatch envelope 형태를 넣습니다.
  expect("정상 2건과 고유 ID") { |events| events.length == 2 && events.map { |e| e.get("[@metadata][document_id]") }.uniq.length == 2 && events.first.get("@timestamp").time.to_i == 1700000000 } # 이벤트 개수·ID·발생 시간을 동시에 확인합니다.
end # 배열 분리 테스트를 마칩니다.
test "깨진 JSON을 격리하고 원문을 보존한다" do # 전처리 오류가 손실로 이어지지 않는지 확인합니다.
  in_event { {"message" => "broken-json", "fields" => {"source_kind" => "guardduty"}} } # JSON이 아닌 문자열을 넣습니다.
  expect("격리 1건과 원문 보존") { |events| events.length == 1 && events.first.get("[event][dataset]") == "aws.quarantine" && events.first.get("[event][original]") == "broken-json" } # 오류 이벤트가 남는지 검증합니다.
end # 오류 보존 테스트를 마칩니다.
