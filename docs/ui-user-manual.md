# UI 使用手冊

本手冊說明如何使用 **Home Network Security Auditor** 的 Streamlit 介面完成
家庭網路安全掃描、查看報告，以及對掃描結果進行後續問答。

## 1. 啟動方式

在專案根目錄執行：

```bash
streamlit run app.py
```

啟動後，瀏覽器會開啟 Streamlit UI。若未自動開啟，可依終端機顯示的
`localhost` URL 手動進入。

## 2. 使用前準備

Live scan 會實際掃描目前所在的區域網路。使用前請確認：

- 只在自己擁有或被授權的網路上執行。
- 已安裝專案依賴與 `nmap`。
- `.env` 已設定 Azure OpenAI 與知識庫相關參數。
- RAG knowledge base 已建置完成，否則 CVE / KB 查詢可能無法正常工作。

如果只是展示 UI 或練習操作，可使用內建 Demo Report，不需要實際掃描網路。

## 3. 介面區域

### 左側 Sidebar：Run

左側欄提供三個主要操作：

- **Start Scan**：執行 live network scan。
- **Demo scenario**：選擇 deterministic demo report。
- **Load Demo Report**：載入選定的 demo report。
- **Reset**：清除目前報告與對話紀錄，回到初始畫面。

### 主畫面

主畫面標題為 **Home Network Security Auditor**。尚未載入報告時，會顯示著陸頁：

- 一條歡迎/引導帶，提示用 **Start Scan** 或 **Load Demo Report** 開始；
- 四張功能卡片：Discover devices、Match real CVEs、Graded A–F report、Grounded Q&A；
- 「How a scan runs」一列說明性事實：
  - **Port scan**：Top 100 ports
  - **OS detection**：依當前權限顯示 `Off · sudo enables`（一般）或 `On · root`（以 `sudo` 啟動時）
  - **Scope**：Local LAN（只掃你所在的本地網段）

載入或完成掃描後，主畫面會改為安全報告與 Follow-up Q&A。

## 4. 執行 Live Scan

1. 在左側 Sidebar 點擊 **Start Scan**。
2. UI 會顯示 **Running scan** 狀態區塊；掃描期間 **Start Scan**／**Load Demo Report**／**Reset** 會暫時停用（Start Scan 變為 **Scanning…**），避免重複觸發。
3. 掃描期間會逐步串流目前進度，例如網路資訊、Wi-Fi、裝置掃描、路由器檢查、CVE 查詢與報告生成。
4. 完成後，畫面會自動顯示 `ScanReport`。
5. 若掃描失敗，UI 會顯示錯誤訊息；可依錯誤內容檢查依賴、權限、`.env` 或網路狀態。

Live scan 預設偏向 demo-friendly 設定：掃描 top 100 ports，且 OS detection 預設關閉，以避免需要 sudo 或管理員權限。若以 `sudo` 啟動（例如 `sudo .venv/bin/python -m streamlit run app.py`），agent 會自動開啟 OS detection，且 nmap 可改用 ARP 探索而掃到更多裝置。

## 5. 載入 Demo Report

Demo Report 適合課堂展示、截圖、測試 UI，以及不想掃描真實網路時使用。

操作方式：

1. 在左側 Sidebar 的 **Demo scenario** 選擇情境。
2. 點擊 **Load Demo Report**。
3. 報告會立即載入到主畫面。

目前提供三種情境：

| 情境 | 預期等級 | 用途 |
| ---- | -------- | ---- |
| Clean network | A | 展示無明顯風險時，系統不會捏造問題。 |
| Risky IoT | B | 展示新版小型 LAN 掃描：2 台裝置、WPA3、FTP/RTSP 服務檢查，以及 Medium/Info 風險維度。 |
| Vulnerable router | D | 展示高風險路由器問題、Telnet、UPnP，以及 CVE 引用。 |

也可以直接用 URL 載入 demo：

```text
http://localhost:8501/?demo=clean_network
http://localhost:8501/?demo=risky_iot
http://localhost:8501/?demo=vulnerable_router
```

若使用不同 Streamlit port，請把 `8501` 改成實際 port。

## 6. 閱讀安全報告

報告區塊依序包含以下內容。

### Security Report

最上方是一個**色階化的等級徽章**（A 綠 → F 紅）與摘要標籤：

- **Overall grade**：整體安全等級，範圍為 A / B / C / D / F。
- **Devices**：掃描到的裝置數量。
- **High**：高風險 finding 數量。
- **Medium**：中風險 finding 數量。
- **Generated**：報告產生時間。

等級意義：

| 等級 | UI 標籤 | 說明 |
| ---- | ------- | ---- |
| A | Secure | 未發現會降低評分的問題。 |
| B | Good | 有 low 或少量 medium finding。 |
| C | Needs improvement | 有 high finding，或 medium finding 數量較多。 |
| D | At risk | 有多個 high finding。 |
| F | Critical | 高風險問題數量達 critical 門檻。 |

### Network

顯示本機網路視角：

- Local IP
- Subnet
- Gateway
- Interface
- DNS
- Medium：Wireless 或 Wired
- Wi-Fi 摘要：SSID、加密方式、頻段、訊號強度
- Router 摘要：型號、韌體版本、管理介面、UPnP 等資訊

### Risk Dimensions

以五個維度整理風險：

- Router vulnerability
- Wi-Fi encryption
- IoT exposure
- Network isolation
- Remote attack surface

每列會顯示該維度的最嚴重等級與 finding 數量。

### Devices

列出掃描到的裝置：

- IP
- Name
- Vendor
- Role
- OS
- Open ports

Gateway 裝置會在 Role 欄標示為 `Gateway`。

### Findings

Findings 會依嚴重度分成四個 tab：

- High
- Medium
- Low
- Info

每個 finding card 會以**嚴重度顏色**標示左側色條（high 紅／medium 琥珀／low 藍／info 灰），內容包含：

- finding 標題
- 嚴重度與風險維度
- affected host / port / SSID
- 說明
- 相關 CVE 與 CVSS 分數
- Recommended action

若沒有 finding，UI 會顯示 **No risks were identified.**

### Markdown report

點開 **Markdown report** 可查看完整 Markdown 版報告。此內容適合複製到課堂報告、作業文件或 demo transcript。

## 7. Follow-up Q&A

報告產生後，下方會出現 **Follow-up Q&A**。

可詢問例如：

- `我的網路拿到什麼等級？主要原因是什麼？`
- `最嚴重的問題是哪一台設備？`
- `我應該先修哪一個問題？`
- `我的 Wi-Fi 加密夠安全嗎？`
- `報告中提到的 CVE 是哪一個？`

回答會根據目前載入的 `ScanReport` 與知識庫內容產生，並以**串流方式逐字顯示**（像打字一樣即時出現）。若 demo report 載入時無法建立 LLM agent，Q&A 輸入框會顯示 **Q&A unavailable**，但報告本身仍可正常瀏覽。

## 8. Reset

點擊左側 Sidebar 的 **Reset** 會清除：

- 目前載入的 report
- agent session
- Q&A 歷史紀錄

Reset 後可重新執行 live scan，或載入不同 demo scenario。

## 9. 常見狀況

### Start Scan 失敗

可能原因：

- `.env` 缺少 Azure OpenAI 設定。
- RAG knowledge base 尚未建立。
- `nmap` 未安裝或無法被系統找到。
- 目前網路權限不足。
- 掃描目標網段無法連線。

### Wi-Fi 顯示 not detected

可能原因：

- 主機使用有線網路。
- 作業系統限制 Wi-Fi 資訊存取。
- macOS 未授權 Location / Wi-Fi 相關權限。

### Q&A unavailable

可能原因：

- LLM client 初始化失敗。
- Azure OpenAI 設定缺漏。

無論用側邊欄按鈕或 `?demo=...` URL 載入 demo report，UI 都會嘗試建立 Q&A
agent；建立失敗時報告仍可正常瀏覽，畫面上會出現警告說明原因。

### 報告中沒有 CVE

可能原因：

- 掃描結果沒有足夠的 product / version 資訊。
- KB 中沒有對應產品或版本的 CVE。
- finding 屬於設定風險，例如 WPA2、UPnP、網路隔離，不一定會有 CVE。

## 10. 建議 Demo 流程

課堂展示可依序使用：

1. `Clean network`：展示乾淨網路與 A 等級。
2. `Risky IoT`：展示 B 等級報告、2 台裝置、WPA3、FTP/RTSP 服務與中文 follow-up Q&A。
3. `Vulnerable router`：展示 high findings、CVE 引用與修復建議。
4. 若時間允許，再執行 **Start Scan** 展示真實 LAN 的 end-to-end 流程。

