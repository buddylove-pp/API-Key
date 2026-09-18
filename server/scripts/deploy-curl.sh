#!/bin/bash
# ============================================================================
# orkestr 一键部署（curl 版）
# ============================================================================
# 为什么有 curl 版：本机 Node 的 fetch（undici）连 api.orkestr.eu 会 10s 超时，
# 而 curl 走代理正常。scripts/deploy-orkestr.mjs 在正常网络下可用，本机用这个。
#
# 实现要点：payload 全程走管道，不落临时文件
#   —— 本机 mktemp 返回 Windows 混合路径、且 node 有 fs shim 拦截写入，
#      落盘方案在这个环境下不可靠。
#
# 用法：
#   ORKESTR_API_KEY=ork_xxx ORKESTR_PROJECT_ID=<uuid> bash scripts/deploy-curl.sh
#
# 可选：
#   SKIP_ENV=1   只部署，不改环境变量
# ============================================================================

set -e

: "${ORKESTR_API_KEY:?缺少 ORKESTR_API_KEY}"
: "${ORKESTR_PROJECT_ID:?缺少 ORKESTR_PROJECT_ID}"

BASE="${ORKESTR_API_BASE:-https://api.orkestr.eu/api}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

auth_curl() {
  curl -s --max-time 90 \
    -H "Authorization: Bearer $ORKESTR_API_KEY" \
    -H "Content-Type: application/json" \
    "$@"
}

echo "==> 读取环境信息"
ENVS_JSON="$(auth_curl "$BASE/projects/$ORKESTR_PROJECT_ID/environments")"
ENV_ID="${ORKESTR_ENV_ID:-$(echo "$ENVS_JSON" | grep -o '"id":"[0-9a-f-]\{36\}"' | head -1 | cut -d'"' -f4)}"
if [ -z "$ENV_ID" ]; then
  echo "!! 找不到环境：$(echo "$ENVS_JSON" | head -c 300)"
  exit 1
fi
echo "    环境 ID: $ENV_ID"

if [ "${SKIP_ENV:-0}" != "1" ]; then
  echo "==> 读取数据库附加组件连接串"
  ADDONS_JSON="$(auth_curl "$BASE/projects/$ORKESTR_PROJECT_ID/addons")"
  DB_URL="$(echo "$ADDONS_JSON" | grep -o '"connection_url":"[^"]*"' | head -1 | cut -d'"' -f4)"
  if [ -z "$DB_URL" ]; then
    echo "!! 未找到 PostgreSQL 附加组件，请先在控制台 Add-ons 里创建"
    exit 1
  fi
  echo "    ${DB_URL:0:40}…"

  echo "==> 写入环境变量（payload 走管道）"
  RESULT="$(
    DB_URL="$DB_URL" node -e '
      const fs = require("fs");
      const env = {};
      for (const line of fs.readFileSync(".env", "utf8").split("\n")) {
        if (!line.includes("=") || line.startsWith("#")) continue;
        const i = line.indexOf("=");
        env[line.slice(0, i).trim()] = line.slice(i + 1).trim();
      }
      if (!env.ADMIN_TOKEN || !env.TICKET_PRIVATE_KEY_PEM) {
        console.error("!! .env 缺少 ADMIN_TOKEN 或 TICKET_PRIVATE_KEY_PEM");
        process.exit(1);
      }
      const vars = {
        DB_DRIVER: "pg",
        DATABASE_URL: process.env.DB_URL,
        ADMIN_TOKEN: env.ADMIN_TOKEN,
        TICKET_PRIVATE_KEY_PEM: env.TICKET_PRIVATE_KEY_PEM,
        AUTO_MIGRATE: "true",
        RATE_LIMIT_MAX: env.RATE_LIMIT_MAX || "60",
        RATE_LIMIT_WINDOW_SEC: env.RATE_LIMIT_WINDOW_SEC || "60",
      };
      // 首次部署用：创建 root 账户（账户表非空时平台侧会忽略，不会覆盖密码）
      if (env.ADMIN_USERNAME) vars.ADMIN_USERNAME = env.ADMIN_USERNAME;
      if (env.ADMIN_PASSWORD) vars.ADMIN_PASSWORD = env.ADMIN_PASSWORD;
      process.stdout.write(JSON.stringify({ env_vars: vars }));
    ' | auth_curl -X PATCH -d @- "$BASE/projects/$ORKESTR_PROJECT_ID/environments/$ENV_ID"
  )"

  if echo "$RESULT" | grep -q '"env_vars"'; then
    echo "    ✓ 已写入（平台侧加密存储）"
  else
    echo "    ✗ 写入失败: $(echo "$RESULT" | head -c 300)"
    exit 1
  fi
fi

echo "==> 触发部署"
DEP="$(auth_curl -X POST -d '{}' "$BASE/projects/$ORKESTR_PROJECT_ID/deploy")"
DEP_ID="$(echo "$DEP" | grep -o '"id":"[0-9a-f-]\{36\}"' | head -1 | cut -d'"' -f4)"
if [ -z "$DEP_ID" ]; then
  echo "    ✗ 触发失败: $(echo "$DEP" | head -c 300)"
  exit 1
fi
echo "    部署 ID: $DEP_ID"

echo "==> 轮询状态"
for i in $(seq 1 40); do
  sleep 15
  R="$(auth_curl "$BASE/projects/$ORKESTR_PROJECT_ID/deployments")"
  ST="$(echo "$R" | grep -o '"status":"[a-z]*"' | head -1 | cut -d'"' -f4)"
  ERR="$(echo "$R" | grep -o '"error_message":"[^"]\{0,200\}' | head -1 | cut -d'"' -f4)"
  echo "    [$((i * 15))s] ${ST:-?}${ERR:+  | $ERR}"

  case "$ST" in
    running|success|live)
      echo
      echo "══════════════════════════════════════════"
      echo "  ✓ 部署成功"
      echo "  https://api-key.orkestr.run/admin"
      echo "══════════════════════════════════════════"
      exit 0
      ;;
    failed|error)
      echo
      echo "  ✗ 部署失败"
      exit 1
      ;;
  esac
done

echo "轮询超时，请到 orkestr 控制台查看"
exit 1
