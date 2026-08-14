#!/bin/bash
# 每日备份 scans.db，保留 7 天（Grok 基线建议）
set -e
DB=/opt/supply-chain-brain/data/scans.db
BK_DIR=/opt/supply-chain-brain/backups
mkdir -p "$BK_DIR"
STAMP=$(date +%Y%m%d)
# 用 sqlite3 在线备份（不锁库）
sqlite3 "$DB" ".backup $BK_DIR/scans_$STAMP.db" 2>/dev/null || cp "$DB" "$BK_DIR/scans_$STAMP.db"
# 保留最近 7 个
ls -t "$BK_DIR"/scans_*.db 2>/dev/null | tail -n +8 | xargs -r rm -f
echo "backup done: $BK_DIR/scans_$STAMP.db"
