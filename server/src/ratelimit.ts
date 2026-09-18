/**
 * 极简固定窗口限流器（进程内）
 *
 * 卡密是 125 bit 随机串，爆破不现实；限流主要是防接口滥用与刷量。
 * 单容器部署下进程内计数够用；将来多实例需换成 Redis。
 */

export class RateLimiter {
  private hits = new Map<string, { count: number; resetAt: number }>();

  constructor(private readonly max: number, private readonly windowSec: number) {}

  /** true = 放行 */
  allow(key: string): boolean {
    const now = Date.now();
    const rec = this.hits.get(key);
    if (rec === undefined || now >= rec.resetAt) {
      this.hits.set(key, { count: 1, resetAt: now + this.windowSec * 1000 });
      return true;
    }
    if (rec.count >= this.max) return false;
    rec.count += 1;
    return true;
  }

  /** 清理过期桶，防止内存无限增长 */
  sweep(): void {
    const now = Date.now();
    for (const [k, v] of this.hits) {
      if (now >= v.resetAt) this.hits.delete(k);
    }
  }
}
