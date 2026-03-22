#!/bin/bash
# NetGuardia 功能測試腳本
# 測試：XDP 封包轉發、Web API、ML 引擎
# 使用 graceful shutdown，所有操作設有 timeout

set -uo pipefail

TIMEOUT=10
NG_API="http://10.10.3.10:8080"
PASS=0
FAIL=0
TESTS=()

run_sudo() {
    sudo "$@" 2>/dev/null
}

ng_exec() {
    run_sudo podman exec netguardia bash -c "$1"
}

router_exec() {
    run_sudo podman exec router bash -c "$1"
}

ext_exec() {
    run_sudo podman exec external bash -c "$1"
}

int_exec() {
    run_sudo podman exec internal bash -c "$1"
}

test_result() {
    local name="$1"
    local result="$2"
    if [ "$result" -eq 0 ]; then
        echo "  ✅ $name"
        PASS=$((PASS + 1))
    else
        echo "  ❌ $name"
        FAIL=$((FAIL + 1))
    fi
    TESTS+=("$name:$result")
}

echo "=========================================="
echo "  NetGuardia 功能測試"
echo "=========================================="
echo ""

# ============================================================
# 1. 基礎檢查
# ============================================================
echo "--- 1. 基礎檢查 ---"

# 1a. 容器運行中
run_sudo podman ps --filter name=netguardia --format "{{.Status}}" | grep -q "Up" 2>/dev/null
test_result "netguardia 容器運行中" $?

# 1b. XDP 程式已附加
ng_exec "ip link show ng-ext 2>/dev/null | grep -q xdp"
test_result "ng-ext XDP 程式已附加" $?

ng_exec "ip link show ng-int 2>/dev/null | grep -q xdp"
test_result "ng-int XDP 程式已附加" $?

# 1c. 管理網路可達
ng_exec "ping -c1 -W $TIMEOUT 10.10.3.1 >/dev/null 2>&1"
test_result "管理網路 (10.10.3.1) 可達" $?

echo ""

# ============================================================
# 2. XDP 封包轉發測試
# ============================================================
echo "--- 2. XDP 封包轉發測試 ---"

# 2a. Router -> Internal (透過 NetGuardia)
router_exec "ping -c 3 -W $TIMEOUT 10.10.2.2 >/dev/null 2>&1"
test_result "Router → Internal ICMP 轉發 (10.10.2.2)" $?

# 2b. Internal -> Router (反向轉發)
int_exec "ping -c 3 -W $TIMEOUT 10.10.2.1 >/dev/null 2>&1"
test_result "Internal → Router ICMP 轉發 (10.10.2.1)" $?

# 2c. External -> Internal (全路徑: external -> router -> netguardia -> internal)
ext_exec "ping -c 3 -W $TIMEOUT 10.10.2.2 >/dev/null 2>&1"
test_result "External → Internal 全路徑 ICMP" $?

# 2d. Internal -> External (全路徑反向)
int_exec "ping -c 3 -W $TIMEOUT 10.10.1.2 >/dev/null 2>&1"
test_result "Internal → External 全路徑 ICMP" $?

# 2e. TCP 轉發 (HTTP)
ext_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' http://10.10.2.2/ 2>/dev/null" | grep -q "200"
test_result "External → Internal HTTP (TCP 轉發)" $?

echo ""

# ============================================================
# 3. Web API 測試
# ============================================================
echo "--- 3. Web API 測試 ---"

# 3a. Health endpoint
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' $NG_API/api/health/status" | grep -q "200"
test_result "GET /api/health/status" $?

# 3b. Health metrics
ng_exec "timeout $TIMEOUT curl -s $NG_API/api/health/metrics" | grep -q "cpu" 2>/dev/null
test_result "GET /api/health/metrics (含 CPU 資訊)" $?

# 3c. Flow stats
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' $NG_API/api/stats/flows" | grep -q "200"
test_result "GET /api/stats/flows" $?

# 3e. Stats summary
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' $NG_API/api/stats/summary" | grep -q "200"
test_result "GET /api/stats/summary" $?

# 3f. ML status
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' $NG_API/api/ml/status" | grep -q "200"
test_result "GET /api/ml/status" $?

# 3g. ACL list
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' $NG_API/api/acl/ipv4/source/whitelist" | grep -q "200"
test_result "GET /api/acl/ipv4/source/whitelist" $?

# 3h. Rate limit config
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' $NG_API/api/rate-limit/config" | grep -q "200"
test_result "GET /api/rate-limit/config" $?

echo ""

# ============================================================
# 4. ACL 功能測試
# ============================================================
echo "--- 4. ACL 功能測試 ---"

# 4a. 添加黑名單規則 (封鎖 10.10.1.5) — API 接收 SocketAddrV4 格式 "ip:port"
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' -X PUT '$NG_API/api/acl/ipv4/source/blacklist' -H 'Content-Type: application/json' -d '\"10.10.1.5:0\"'" | grep -q "200"
test_result "PUT ACL 黑名單規則 (封鎖 10.10.1.5)" $?

# 4b. 驗證封鎖生效 (10.10.1.5 不該能 ping 到 internal)
sleep 1
ext_exec "ping -c 2 -W 3 -I 10.10.1.5 10.10.2.2 >/dev/null 2>&1" && BLOCKED=1 || BLOCKED=0
test_result "10.10.1.5 被封鎖 (ping 失敗)" $BLOCKED

# 4c. 未封鎖的 IP 仍然可達
ext_exec "ping -c 2 -W $TIMEOUT -I 10.10.1.2 10.10.2.2 >/dev/null 2>&1"
test_result "10.10.1.2 未受影響 (ping 成功)" $?

# 4d. 移除黑名單規則
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' -X DELETE '$NG_API/api/acl/ipv4/source/blacklist' -H 'Content-Type: application/json' -d '\"10.10.1.5:0\"'" | grep -q "200"
test_result "DELETE ACL 黑名單規則 (解除 10.10.1.5)" $?

# 4e. 驗證解除封鎖
sleep 1
ext_exec "ping -c 2 -W $TIMEOUT -I 10.10.1.5 10.10.2.2 >/dev/null 2>&1"
test_result "10.10.1.5 解除封鎖 (ping 恢復)" $?

echo ""

# ============================================================
# 5. Rate Limit 測試
# ============================================================
echo "--- 5. Rate Limit 測試 ---"

# 5a. 讀取當前 rate limit 設定
RL_CONFIG=$(ng_exec "timeout $TIMEOUT curl -s $NG_API/api/rate-limit/config")
echo "$RL_CONFIG" | grep -q "packet_rate" 2>/dev/null
test_result "Rate limit 設定可讀取" $?

echo ""

# ============================================================
# 6. ML 引擎測試
# ============================================================
echo "--- 6. ML 引擎測試 ---"

ML_STATUS=$(ng_exec "timeout $TIMEOUT curl -s $NG_API/api/ml/status")
echo "$ML_STATUS" | grep -q "active\|logging\|disabled" 2>/dev/null
test_result "ML 引擎狀態可查詢" $?

# 檢查 traffic log 是否在寫入 (traffic_logging_mode = true)
ng_exec "test -f /root/NetGuardia/traffic_log.csv && wc -l < /root/NetGuardia/traffic_log.csv || echo 0" | grep -qv "^0$" 2>/dev/null
test_result "Traffic log CSV 有寫入資料" $?

echo ""

# ============================================================
# 7. WebSocket 測試
# ============================================================
echo "--- 7. WebSocket 測試 ---"

# 簡單測試 WS endpoint 是否回應 (upgrade request)
# curl -sv 輸出 status code 到 stderr，101 Switching Protocols 表示成功
WS_CODE=$(ng_exec "timeout 3 curl -s -o /dev/null -w '%{http_code}' -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Sec-WebSocket-Key: dGVzdA==' -H 'Sec-WebSocket-Version: 13' $NG_API/ws/health 2>/dev/null || true")
echo "$WS_CODE" | grep -q "101"
test_result "WebSocket /ws/health 升級成功 (101)" $?

echo ""

# ============================================================
# 8. GeoIP 國家封鎖 API 測試
# ============================================================
echo "--- 8. GeoIP 國家封鎖 API 測試 ---"

# 8a. 查詢目前封鎖的國家列表
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' $NG_API/api/acl/geo/blocked" | grep -q "200"
test_result "GET /api/acl/geo/blocked" $?

# 8b. 封鎖國家 (CN, RU) — GeoIP rebuild 需要掃描 MaxMind DB，timeout 加長到 30s
ng_exec "timeout 30 curl -s -o /dev/null -w '%{http_code}' -X PUT '$NG_API/api/acl/geo/block' -H 'Content-Type: application/json' -d '{\"country_codes\":[\"CN\",\"RU\"]}'" | grep -q "200"
test_result "PUT /api/acl/geo/block 封鎖 CN, RU" $?

# 8c. 驗證封鎖列表包含 CN
GEO_BLOCKED=$(ng_exec "timeout $TIMEOUT curl -s $NG_API/api/acl/geo/blocked")
echo "$GEO_BLOCKED" | grep -q "CN" 2>/dev/null
test_result "封鎖列表包含 CN" $?

# 8d. 回傳包含 total_prefixes
GEO_PUT_RESP=$(ng_exec "timeout 30 curl -s -X PUT '$NG_API/api/acl/geo/block' -H 'Content-Type: application/json' -d '{\"country_codes\":[\"KP\"]}'")
echo "$GEO_PUT_RESP" | grep -q "total_prefixes" 2>/dev/null
test_result "PUT 回傳 total_prefixes 欄位" $?

# 8e. 解除封鎖
ng_exec "timeout 30 curl -s -o /dev/null -w '%{http_code}' -X DELETE '$NG_API/api/acl/geo/unblock' -H 'Content-Type: application/json' -d '{\"country_codes\":[\"CN\",\"RU\",\"KP\"]}'" | grep -q "200"
test_result "DELETE /api/acl/geo/unblock 清除所有 GeoIP 規則" $?

# 8f. 驗證清空
GEO_AFTER=$(ng_exec "timeout $TIMEOUT curl -s $NG_API/api/acl/geo/blocked")
echo "$GEO_AFTER" | grep -q '"blocked_countries":\[\]' 2>/dev/null || echo "$GEO_AFTER" | grep -q '"blocked_countries": \[\]' 2>/dev/null
test_result "封鎖列表已清空" $?

echo ""

# ============================================================
# 9. DNS 黑名單 API 測試
# ============================================================
echo "--- 9. DNS 黑名單 API 測試 ---"

# 9a. 查詢 DNS 黑名單
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' $NG_API/api/filter/dns/blacklist" | grep -q "200"
test_result "GET /api/filter/dns/blacklist" $?

# 9b. 新增域名到黑名單
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' -X PUT '$NG_API/api/filter/dns/blacklist' -H 'Content-Type: application/json' -d '{\"domains\":[\"malware.example.com\",\"phishing.test.org\"]}'" | grep -q "200"
test_result "PUT /api/filter/dns/blacklist 新增域名" $?

# 9c. 驗證黑名單已更新
DNS_DOMAINS=$(ng_exec "timeout $TIMEOUT curl -s $NG_API/api/filter/dns/blacklist")
echo "$DNS_DOMAINS" | grep -q "malware.example.com" 2>/dev/null
test_result "黑名單包含 malware.example.com" $?

# 9d. 移除域名
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' -X DELETE '$NG_API/api/filter/dns/blacklist' -H 'Content-Type: application/json' -d '{\"domains\":[\"phishing.test.org\"]}'" | grep -q "200"
test_result "DELETE 移除 phishing.test.org" $?

# 9e. 驗證移除結果
DNS_AFTER=$(ng_exec "timeout $TIMEOUT curl -s $NG_API/api/filter/dns/blacklist")
echo "$DNS_AFTER" | grep -q "malware.example.com" 2>/dev/null
test_result "移除後仍包含 malware.example.com" $?

# 9f. 清除所有 DNS 黑名單
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' -X DELETE '$NG_API/api/filter/dns/blacklist' -H 'Content-Type: application/json' -d '{\"domains\":[\"malware.example.com\"]}'" | grep -q "200"
test_result "清除所有 DNS 黑名單規則" $?

echo ""

# ============================================================
# 10. DNS 黑名單封鎖流量驗證
# ============================================================
echo "--- 10. DNS 黑名單封鎖流量驗證 ---"

# 10a. 新增測試域名到黑名單
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' -X PUT '$NG_API/api/filter/dns/blacklist' -H 'Content-Type: application/json' -d '{\"domains\":[\"evil.example.com\"]}'" | grep -q "200"
test_result "新增 evil.example.com 到 DNS 黑名單" $?

# 10b. 對黑名單域名的 DNS 查詢應被丟棄 (timeout)
sleep 1
ext_exec "timeout 3 dig @10.10.2.2 evil.example.com +time=2 +tries=1 >/dev/null 2>&1" && DNS_BLOCKED=1 || DNS_BLOCKED=0
test_result "evil.example.com DNS 查詢被封鎖" $DNS_BLOCKED

# 10c. 子域名也應被封鎖
ext_exec "timeout 3 dig @10.10.2.2 sub.evil.example.com +time=2 +tries=1 >/dev/null 2>&1" && SUB_BLOCKED=1 || SUB_BLOCKED=0
test_result "sub.evil.example.com 子域名也被封鎖" $SUB_BLOCKED

# 10d. 清除
ng_exec "timeout $TIMEOUT curl -s -o /dev/null -w '%{http_code}' -X DELETE '$NG_API/api/filter/dns/blacklist' -H 'Content-Type: application/json' -d '{\"domains\":[\"evil.example.com\"]}'" | grep -q "200"
test_result "清除 DNS 黑名單測試規則" $?

echo ""

# ============================================================
# 結果總結
# ============================================================
echo "=========================================="
echo "  測試結果: $PASS 通過 / $FAIL 失敗 / $((PASS + FAIL)) 總計"
echo "=========================================="

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "失敗的測試："
    for t in "${TESTS[@]}"; do
        name="${t%:*}"
        result="${t##*:}"
        if [ "$result" -ne 0 ]; then
            echo "  ❌ $name"
        fi
    done
fi

exit $FAIL
