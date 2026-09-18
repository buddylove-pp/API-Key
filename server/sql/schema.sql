-- 卡密授权系统 · PostgreSQL Schema
-- 首次部署时由服务自动执行（AUTO_MIGRATE=true），也可手动 psql 执行

-- ============ 软件注册表 ============
-- 卡密的 product 维度必须来自这里，避免手输错字导致卡密和软件对不上。
-- 注册方式：客户端首次调用 /api/v1/activate 上报未知标识时自动登记为 pending，
-- 管理员在后台确认后置为 active，之后才能为该软件生成卡密。
CREATE TABLE IF NOT EXISTS products (
  id            BIGSERIAL PRIMARY KEY,
  code          TEXT      NOT NULL UNIQUE,  -- 软件标识，客户端上报的值
  name          TEXT      NOT NULL,         -- 展示名，后台下拉框显示
  status        TEXT      NOT NULL DEFAULT 'active',  -- active | pending | disabled
  note          TEXT,
  created_at    BIGINT    NOT NULL,
  first_seen_at BIGINT,                     -- 首次被客户端上报的时间
  first_seen_ip TEXT,
  app_version   TEXT                        -- 首次上报时的客户端版本
);

CREATE INDEX IF NOT EXISTS idx_products_status ON products (status);

-- 预置内置测试客户端
INSERT INTO products (code, name, status, note, created_at)
VALUES ('license-tester', '卡密授权测试客户端', 'active', '仓库内置的测试工具', EXTRACT(EPOCH FROM NOW())::BIGINT)
ON CONFLICT (code) DO NOTHING;

-- ============ 管理员账户 ============
-- 账户密码登录 → 最高权限，可在界面里签发下级令牌
CREATE TABLE IF NOT EXISTS admin_users (
  id            BIGSERIAL PRIMARY KEY,
  username      TEXT      NOT NULL UNIQUE,
  password_hash TEXT      NOT NULL,   -- scrypt 格式：scrypt$N$r$p$salt$hash
  role          TEXT      NOT NULL DEFAULT 'root',   -- root | operator | readonly
  disabled      BOOLEAN   NOT NULL DEFAULT FALSE,
  created_at    BIGINT    NOT NULL,
  last_login_at BIGINT
);

-- ============ 管理员令牌 ============
-- 由账户签发，带权限角色与有效期。只存哈希，明文只在签发时返回一次。
CREATE TABLE IF NOT EXISTS admin_tokens (
  id           BIGSERIAL PRIMARY KEY,
  token_hash   TEXT      NOT NULL UNIQUE,  -- SHA-256(令牌)，不存明文
  token_prefix TEXT      NOT NULL,         -- 前 12 位，便于在列表里辨认
  name         TEXT,                       -- 备注，例如「给运维用」
  role         TEXT      NOT NULL,         -- 该令牌的权限角色
  created_by   TEXT      NOT NULL,         -- 签发者用户名
  created_at   BIGINT    NOT NULL,
  expires_at   BIGINT    NOT NULL,
  revoked      BOOLEAN   NOT NULL DEFAULT FALSE,
  last_used_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_admin_tokens_hash ON admin_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_admin_tokens_expires ON admin_tokens (expires_at);

-- ============ 卡密表 ============
-- 授权策略全部可配置，不写死在代码里
CREATE TABLE IF NOT EXISTS licenses (
  id                 BIGSERIAL   PRIMARY KEY,
  key_hash           TEXT        NOT NULL UNIQUE,   -- SHA-256(规范化卡密)，不存明文
  key_prefix         TEXT        NOT NULL,          -- 前 8 位明文，便于客服定位
  status             TEXT        NOT NULL DEFAULT 'unused',  -- unused | active | banned

  -- ▼ 软件维度：卡密绑定到具体产品，防止 A 软件的卡密拿到 B 软件上用
  product            TEXT        NOT NULL DEFAULT 'default',

  -- ▼ 授权策略（生成卡密时设定，后台可改）
  max_devices        INTEGER     NOT NULL DEFAULT 1,     -- 同时可绑定设备数
  max_activations    INTEGER     NOT NULL DEFAULT 1,     -- 可激活次数，用一次少一次
  activation_days    INTEGER     NOT NULL DEFAULT 365,   -- 每次激活授予的天数
  max_unbinds        INTEGER     NOT NULL DEFAULT 3,     -- 可解绑次数上限
  refund_on_unbind   BOOLEAN     NOT NULL DEFAULT TRUE,  -- 解绑是否返还激活次数

  -- ▼ 运行时计数
  activation_count   INTEGER     NOT NULL DEFAULT 0,
  unbind_count       INTEGER     NOT NULL DEFAULT 0,

  -- ▼ 时间（Unix 秒）
  created_at         BIGINT      NOT NULL,
  first_activated_at BIGINT,
  expires_at         BIGINT,                             -- 卡密绝对到期；NULL = 不限制
  note               TEXT
);

CREATE INDEX IF NOT EXISTS idx_licenses_prefix ON licenses (key_prefix);
CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses (status);
CREATE INDEX IF NOT EXISTS idx_licenses_product ON licenses (product);

-- ============ 设备绑定表 ============
CREATE TABLE IF NOT EXISTS bindings (
  id          BIGSERIAL PRIMARY KEY,
  license_id  BIGINT    NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  device_fp   TEXT      NOT NULL,   -- 设备指纹哈希（客户端上报，只存哈希）
  device_name TEXT,                 -- 用户可读设备名，便于自助解绑时辨认
  first_seen  BIGINT    NOT NULL,
  last_seen   BIGINT    NOT NULL,
  UNIQUE (license_id, device_fp)
);

CREATE INDEX IF NOT EXISTS idx_bindings_license ON bindings (license_id);

-- ============ 审计日志 ============
-- 排查纠纷必需：谁在什么时候用什么设备做了什么
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGSERIAL PRIMARY KEY,
  license_id  BIGINT,
  event       TEXT      NOT NULL,   -- activate | heartbeat | unbind | ban | unban | generate
  device_fp   TEXT,
  ip          TEXT,
  app_version TEXT,
  detail      TEXT,
  created_at  BIGINT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_license ON audit_log (license_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log (created_at DESC);
