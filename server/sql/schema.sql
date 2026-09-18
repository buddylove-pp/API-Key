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
  last_used_at BIGINT,
  -- 非空表示这是「账户密码登录」产生的会话令牌，归属该账户；
  -- 为空表示这是管理员手动签发的下级令牌。
  -- 只有前者能管理令牌 —— 令牌不能派生令牌。
  owner_username TEXT
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

  -- ▼ 定期校验（两种排期方式二选一，由 check_mode 决定）
  --   'frequency' 定频率：把 activation_days 等分成 N 段，每段到期校验一次
  --               N = 1 → 不触发定期校验（激活那一次就算完了）
  --               N = 10 且 activation_days = 100 → 每 10 天校验一次
  --   'interval'  定时间：直接指定每隔多少天校验一次，与总时长无关
  --               D = 0 → 不触发定期校验
  check_mode           TEXT      NOT NULL DEFAULT 'frequency',
  check_frequency      INTEGER   NOT NULL DEFAULT 1,
  check_interval_days  INTEGER   NOT NULL DEFAULT 0,
  -- 提前提醒比例（%）：在下次校验日之前这么多比例的时间开始提醒。0 = 不提醒
  check_remind_percent INTEGER   NOT NULL DEFAULT 20,

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

-- ============ 设备绑定 / 授权表 ============
-- 一行 = 一台设备在一个卡密下的授权。定期校验的排期也记在这里。
CREATE TABLE IF NOT EXISTS bindings (
  id                     BIGSERIAL PRIMARY KEY,
  license_id             BIGINT    NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  device_fp              TEXT      NOT NULL,   -- 设备指纹哈希（只存哈希，不上报原始硬件信息）
  device_name            TEXT,                 -- 用户可读设备名，便于自助解绑时辨认
  first_seen             BIGINT    NOT NULL,   -- 首次激活时间（时间锚点，不可变）
  last_seen              BIGINT    NOT NULL,

  -- ▼ 授权期：激活时一次算定，之后不再受卡密自身有效期影响
  entitlement_expires_at BIGINT,               -- = first_seen + activation_days

  -- ▼ 定期校验排期
  check_frequency        INTEGER   NOT NULL DEFAULT 1,
  check_interval_days    INTEGER   NOT NULL DEFAULT 0,   -- 周期（天），0 = 不校验
  check_remind_percent   INTEGER   NOT NULL DEFAULT 20,
  last_check_at          BIGINT,               -- 上次校验时间（激活时 = first_seen）
  next_check_at          BIGINT,               -- 计划下次校验；NULL = 不校验
  check_state            TEXT      NOT NULL DEFAULT 'active',  -- active | due | overdue
  overdue_since          BIGINT,               -- 进入超期状态的时间

  UNIQUE (license_id, device_fp)
);

CREATE INDEX IF NOT EXISTS idx_bindings_license ON bindings (license_id);

-- ============ 老库升级（幂等） ============
-- ⚠️ 顺序至关重要：CREATE TABLE IF NOT EXISTS 不会给已存在的表补列，
-- 所以老库上必须靠这些 ALTER 把新列加上；而任何依赖新列的语句
-- （建索引、回填 UPDATE）都必须排在 ALTER 之后。
-- 否则整批多语句查询会因一个报错全部回滚，迁移等于没做。
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS check_mode           TEXT NOT NULL DEFAULT 'frequency';
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS check_frequency      INTEGER NOT NULL DEFAULT 1;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS check_interval_days  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE licenses ADD COLUMN IF NOT EXISTS check_remind_percent INTEGER NOT NULL DEFAULT 20;

ALTER TABLE bindings ADD COLUMN IF NOT EXISTS entitlement_expires_at BIGINT;
ALTER TABLE bindings ADD COLUMN IF NOT EXISTS check_frequency        INTEGER NOT NULL DEFAULT 1;
ALTER TABLE bindings ADD COLUMN IF NOT EXISTS check_interval_days    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bindings ADD COLUMN IF NOT EXISTS check_remind_percent   INTEGER NOT NULL DEFAULT 20;
ALTER TABLE bindings ADD COLUMN IF NOT EXISTS last_check_at          BIGINT;
ALTER TABLE bindings ADD COLUMN IF NOT EXISTS next_check_at          BIGINT;
ALTER TABLE bindings ADD COLUMN IF NOT EXISTS check_state            TEXT NOT NULL DEFAULT 'active';
ALTER TABLE bindings ADD COLUMN IF NOT EXISTS overdue_since          BIGINT;

ALTER TABLE admin_tokens ADD COLUMN IF NOT EXISTS owner_username TEXT;

-- 依赖新列的索引，必须放在 ALTER 之后
CREATE INDEX IF NOT EXISTS idx_bindings_next_check ON bindings (next_check_at);

-- 老数据补算授权到期时间（激活时间 + 卡密授予天数）
UPDATE bindings b
   SET entitlement_expires_at = b.first_seen + (l.activation_days * 86400)
  FROM licenses l
 WHERE b.license_id = l.id
   AND b.entitlement_expires_at IS NULL;

-- 老数据补 last_check_at
UPDATE bindings SET last_check_at = first_seen WHERE last_check_at IS NULL;

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
