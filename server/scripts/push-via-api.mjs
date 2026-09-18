#!/usr/bin/env node
/**
 * 通过 GitHub Git Data API 推送提交
 *
 * 什么时候用：`github.com:443` 连不上（git push 报 Failed to connect），
 * 但 `api.github.com` 仍然可达时。用 REST API 手工造一个 commit 顶上，
 * 效果与 git push 等价，只是走的是 API 而非 git 协议。
 *
 * 用法：
 *   GH_TOKEN=ghp_xxx node scripts/push-via-api.mjs
 *
 * 可选：
 *   GH_OWNER / GH_REPO / GH_BRANCH  默认 buddylove-pp / API-Key / main
 *   BASE_SHA                        远端当前 commit（默认从 API 查）
 *   DRY_RUN=1                       只打印将要提交的文件，不真正提交
 */

import { readFileSync, existsSync, unlinkSync } from "node:fs";
import { execFileSync } from "node:child_process";

const TOKEN = process.env.GH_TOKEN;
if (!TOKEN) {
  console.error("缺少 GH_TOKEN");
  process.exit(1);
}

const OWNER = process.env.GH_OWNER || "buddylove-pp";
const REPO = process.env.GH_REPO || "API-Key";
const BRANCH = process.env.GH_BRANCH || "main";
const API = "https://api.github.com";

const headers = {
  Authorization: `Bearer ${TOKEN}`,
  Accept: "application/vnd.github+json",
  "User-Agent": "license-server-deploy",
  "Content-Type": "application/json",
};

/**
 * 用 curl 而不是 fetch。
 * 原因：本机 Node 的 undici 直连 api.github.com 会 10s 连接超时，
 * 而 curl --noproxy 走同一张网卡却能通 —— 实测差异，不是配置问题。
 */
function gh(path, init = {}) {
  const args = [
    "-s", "--noproxy", "*", "--max-time", "120",
    "-X", init.method ?? "GET",
    "-w", "\n__STATUS__%{http_code}",
  ];
  for (const [k, v] of Object.entries(headers)) args.push("-H", `${k}: ${v}`);
  if (init.body !== undefined) args.push("-d", init.body);
  args.push(API + path);

  const raw = execFileSync("curl", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const idx = raw.lastIndexOf("\n__STATUS__");
  const body = idx >= 0 ? raw.slice(0, idx) : raw;
  const status = idx >= 0 ? Number(raw.slice(idx + 11)) : 0;

  let json = null;
  try {
    json = JSON.parse(body);
  } catch {
    /* 非 JSON */
  }

  if (status < 200 || status >= 300) {
    throw new Error(`${init.method ?? "GET"} ${path} → HTTP ${status}\n${body.slice(0, 400)}`);
  }
  return json;
}

function git(args) {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}

// ---------- 1. 远端当前状态 ----------

console.log("==> 读取远端 ref");
const ref = await gh(`/repos/${OWNER}/${REPO}/git/ref/heads/${BRANCH}`);
const baseSha = process.env.BASE_SHA || ref.object.sha;
console.log(`    远端 HEAD: ${baseSha.slice(0, 7)}`);

const baseCommit = await gh(`/repos/${OWNER}/${REPO}/git/commits/${baseSha}`);
const baseTree = baseCommit.tree.sha;

const localHead = git(["rev-parse", "HEAD"]);
console.log(`    本地 HEAD: ${localHead.slice(0, 7)}`);

if (baseSha === localHead) {
  console.log("    远端已是最新，无需推送");
  process.exit(0);
}

// ---------- 2. 变更文件 ----------

const files = git(["diff", "--name-only", baseSha, localHead])
  .split("\n")
  .map((s) => s.trim())
  .filter(Boolean);

if (files.length === 0) {
  console.log("    没有文件差异，无需推送");
  process.exit(0);
}

console.log(`==> 待推送 ${files.length} 个文件`);
for (const f of files) console.log(`    ${f}`);

if (process.env.DRY_RUN === "1") {
  console.log("DRY_RUN=1，到此为止");
  process.exit(0);
}

// ---------- 3. 建 blob ----------

console.log("==> 上传文件内容");
const treeItems = [];
for (const path of files) {
  if (!existsSync(path)) {
    // 删除的文件：tree 里给 null sha 表示删除
    treeItems.push({ path, mode: "100644", type: "blob", sha: null });
    console.log(`    - ${path}（删除）`);
    continue;
  }
  const content = readFileSync(path);
  const blob = await gh(`/repos/${OWNER}/${REPO}/git/blobs`, {
    method: "POST",
    body: JSON.stringify({ content: content.toString("base64"), encoding: "base64" }),
  });
  treeItems.push({ path, mode: "100644", type: "blob", sha: blob.sha });
  console.log(`    ✓ ${path}（${content.length} 字节）`);
}

// ---------- 4. 建 tree ----------

console.log("==> 创建 tree");
const tree = await gh(`/repos/${OWNER}/${REPO}/git/trees`, {
  method: "POST",
  body: JSON.stringify({ base_tree: baseTree, tree: treeItems }),
});
console.log(`    tree ${tree.sha.slice(0, 7)}`);

// ---------- 5. 建 commit ----------

const message = git(["log", "-1", "--pretty=%B"]);
console.log("==> 创建 commit");
const commit = await gh(`/repos/${OWNER}/${REPO}/git/commits`, {
  method: "POST",
  body: JSON.stringify({ message, tree: tree.sha, parents: [baseSha] }),
});
console.log(`    commit ${commit.sha.slice(0, 7)}`);

// ---------- 6. 更新 ref ----------

console.log("==> 更新分支 ref");
await gh(`/repos/${OWNER}/${REPO}/git/refs/heads/${BRANCH}`, {
  method: "PATCH",
  body: JSON.stringify({ sha: commit.sha, force: false }),
});

// 本地 ref 同步，避免下次 diff 基线不对
try {
  git(["update-ref", `refs/remotes/origin/${BRANCH}`, commit.sha]);
} catch {
  /* 没有 origin remote 就算了 */
}

console.log("\n══════════════════════════════════════════");
console.log(`  ✓ 已推送到 ${OWNER}/${REPO}@${BRANCH}`);
console.log(`    ${baseSha.slice(0, 7)} → ${commit.sha.slice(0, 7)}`);
console.log("══════════════════════════════════════════");
