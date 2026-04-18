# Heartbleed Test Environment

這個目錄包含用於測試 tlsscan Heartbleed 檢測功能的 Docker 環境。

## ⚠️ 安全警告

**這個環境故意包含易受攻擊的 OpenSSL 版本（CVE-2014-0160）！**

- 僅用於測試和教育目的
- 不要在生產環境中使用
- 不要暴露到公共網路
- 測試完成後請停止容器

## 快速開始

### 1. 構建和啟動測試環境

```bash
cd docker
./test-heartbleed.sh
```

這個腳本會：
- 構建包含易受攻擊 OpenSSL 1.0.1f 的 Docker 容器
- 啟動運行在 localhost:8443 的測試伺服器
- 自動執行 tlsscan 進行 Heartbleed 檢測
- 顯示測試結果

### 2. 手動測試

如果你想手動控制測試過程：

```bash
# 構建容器
docker-compose build heartbleed-server

# 啟動伺服器
docker-compose up -d heartbleed-server

# 等待伺服器啟動
sleep 10

# 使用 tlsscan 測試
../target/debug/tlsscan localhost:8443 --timeout 10

# 停止伺服器
docker-compose down
```

### 3. 其他測試工具

你也可以使用其他工具驗證 Heartbleed 漏洞：

```bash
# 使用 OpenSSL s_client
openssl s_client -connect localhost:8443 -tlsextdebug

# 使用 nmap（如果已安裝）
nmap -p 8443 --script ssl-heartbleed localhost

# 使用 testssl.sh（如果已安裝）
testssl.sh localhost:8443
```

## 預期結果

### tlsscan 應該檢測到：

- ✅ **Heartbleed (CVE-2014-0160): VULNERABLE**
- ⚠️ 顯示關鍵安全警告
- 🔴 在 Summary 中標記為嚴重問題

### 如果檢測失敗：

這可能表示：
1. 我們的檢測邏輯需要改進
2. Docker 容器沒有正確啟動
3. 網路連接問題

## 故障排除

### 檢查容器狀態
```bash
docker-compose ps
docker-compose logs heartbleed-server
```

### 檢查連接
```bash
# 測試基本連接
telnet localhost 8443

# 檢查 TLS 連接
openssl s_client -connect localhost:8443 -servername localhost
```

### 檢查 OpenSSL 版本
```bash
docker-compose exec heartbleed-server /usr/local/openssl-vulnerable/bin/openssl version -a
```

## 技術細節

### 易受攻擊的配置
- OpenSSL 版本：1.0.1f（易受 Heartbleed 攻擊）
- 啟用 heartbeat 擴展
- 支援 TLS 1.2
- 使用自簽名證書

### Docker 容器規格
- 基於 Ubuntu 14.04（該時期的系統）
- 編譯啟用 heartbeat 的 OpenSSL 1.0.1f
- 運行 `openssl s_server` 作為測試伺服器
- 暴露埠 8443

## 清理

測試完成後，請停止並移除容器：

```bash
docker-compose down
docker rmi $(docker images -q -f "dangling=true")  # 清理未使用的映像
```

## 參考資源

- [CVE-2014-0160 詳情](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160)
- [Heartbleed.com](https://heartbleed.com/)
- [OpenSSL 安全公告](https://www.openssl.org/news/secadv/20140407.txt)