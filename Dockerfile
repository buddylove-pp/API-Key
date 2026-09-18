# ============================================================================
# 仓库根 Dockerfile
# ============================================================================
# 为什么放在根目录？
# orkestr 只扫描仓库根目录找构建入口，而应用代码在 server/ 子目录。
# 与其依赖平台的「构建路径」配置（API 不可写），不如在根目录放一个转发构建。
#
# 实际服务代码在 server/，完整的 Dockerfile 也在那里（本地构建用）。
# 两个文件内容等价，改任意一个都要同步另一个。
# ============================================================================

# ---------- 构建阶段 ----------
FROM node:22-alpine AS build
WORKDIR /app

COPY server/package.json server/package-lock.json* ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund

COPY server/tsconfig.json ./
COPY server/src ./src
RUN npm run build

# ---------- 运行阶段 ----------
FROM node:22-alpine
WORKDIR /app

ENV NODE_ENV=production

COPY server/package.json server/package-lock.json* ./
RUN npm ci --omit=dev --no-audit --no-fund || npm install --omit=dev --no-audit --no-fund

COPY --from=build /app/dist ./dist
COPY server/sql ./sql
COPY server/public ./public

# 以非 root 运行
USER node

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/index.js"]
