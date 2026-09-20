#!/usr/bin/env node
/**
 * 通过 GitHub REST API 推送（github.com 不可达时的备用通道）
 *
 * 什么时候用：`github.com:443` 连不上（git push 报 Failed to connect），
 * 但 `api.github.com` 仍然可达。
 *
 * 为什么不直接用 scripts/push-via-api.mjs：
 *   那个脚本用 execFileSync 调 curl，把 base64 内容当**命令行参数**传。
 *   admin.html 有 100KB+，base64 之后 130KB+，
 *   远超 Windows 命令行长度上限（约 32KB），直接 E2BIG 失败。
 *   这里改用 fetch，内容放在请求体里，没有长度问题。
 *
 * 用法：
 *   GH_TOKEN=ghp_xxx node dev/push-via-api-fetch.mjs
 *
 * 可选：
 *   GH_OWNER / GH_REPO / GH_BRANCH  默认 buddylove-pp / API-Key / main
 *   DRY_RUN=1                       只列出将要提交的文件
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const TOKEN = process.env.GH_TOKEN;
if (!TOKEN) {
  console.error("缺少 GH_TOKEN 环境变量");
  process.exit(1);
}

const OWNER = process.env.GH_OWNER || "buddylove-pp";
const REPO = process.env.GH_REPO || "API-Key";
const BRANCH = process.env.GH_BRANCH || "main";
const DRY_RUN = process.env.DRY_RUN === "1";

const API = `https://api.github.com/repos/${OWNER}/${REPO}`;
const HEADERS = {
  Authorization: `Bearer ${TOKEN}`,
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "User-Agent": "workbuddy-push",
};

const root = process.cwd();

function git(...args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim();
}

async function gh(path, init = {}) {
  const res = await fetch(API + path, {
    ...init,
    headers: { ...HEADERS, "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`GitHub API ${path} → HTTP ${res.status}: ${text.slice(0, 300)}`);
  }
  return text === "" ? null : JSON.parse(text);
}

/** 列出相对远端要改的文件（新增/修改/删除） */
function changedFiles(baseSha) {
  const out = git("diff", "--name-status", baseSha, "HEAD");
  return out
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [status, ...rest] = line.split("\t");
      return { status: status[0], path: rest.join("\t") };
    });
}

async function main() {
  // 远端当前 HEAD
  const ref = await gh(`/git/ref/heads/${BRANCH}`);
  const baseSha = ref.object.sha;
  const localSha = git("rev-parse", "HEAD");

  if (baseSha === localSha) {
    console.log("远端已是最新，无需推送");
    return;
  }

  const message = git("log", "-1", "--pretty=%B");
  const changes = changedFiles(baseSha);

  console.log(`远端  ${baseSha.slice(0, 7)}`);
  console.log(`本地  ${localSha.slice(0, 7)}`);
  console.log(`变更  ${changes.length} 个文件`);
  changes.slice(0, 20).forEach((c) => console.log(`  ${c.status}  ${c.path}`));
  if (changes.length > 20) console.log(`  …另有 ${changes.length - 20} 个`);

  if (DRY_RUN) {
    console.log("\nDRY_RUN=1，未真正提交");
    return;
  }

  // 1) 逐个建 blob
  const treeEntries = [];
  for (const c of changes) {
    if (c.status === "D") {
      treeEntries.push({ path: c.path, mode: "100644", type: "blob", sha: null });
      continue;
    }
    const content = readFileSync(join(root, c.path));
    const blob = await gh("/git/blobs", {
      method: "POST",
      body: JSON.stringify({ content: content.toString("base64"), encoding: "base64" }),
    });
    treeEntries.push({ path: c.path, mode: "100644", type: "blob", sha: blob.sha });
    console.log(`  ✓ blob ${c.path}`);
  }

  // 2) 建 tree（基于远端 HEAD 的 tree，保留未改动的文件）
  const baseCommit = await gh(`/git/commits/${baseSha}`);
  const tree = await gh("/git/trees", {
    method: "POST",
    body: JSON.stringify({ base_tree: baseCommit.tree.sha, tree: treeEntries }),
  });

  // 3) 建 commit
  const commit = await gh("/git/commits", {
    method: "POST",
    body: JSON.stringify({ message, tree: tree.sha, parents: [baseSha] }),
  });

  // 4) 移动分支引用
  await gh(`/git/refs/heads/${BRANCH}`, {
    method: "PATCH",
    body: JSON.stringify({ sha: commit.sha }),
  });

  console.log(`\n✓ 已推送 ${commit.sha.slice(0, 7)} → ${OWNER}/${REPO}@${BRANCH}`);
}

main().catch((e) => {
  console.error("推送失败:", e instanceof Error ? e.message : e);
  process.exit(1);
});
