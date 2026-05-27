
# LLM-Powered Home Network Security Auditor
### 基於大型語言模型的家庭網路資安自動化健檢系統
**Date**: 2026 / 05 / 27

---

### Table of Contents
1. 專案概述
    * 1.1 研究背景與動機
    * 1.2 專案目標
    * 1.3 預期成果
2. 系統架構設計
    * 2.1 整體架構總覽
        * 2.1.1 架構圖說明
    * 2.2 模組詳細設計
        * 模組一：前端使用者介面
        * 模組二：LLM Agent 核心層
        * 模組三：工具執行層
        * 模組四：RAG 知識庫層
3. 掃描內容與分析維度
    * 3.1 自動掃描蒐集內容
        * Layer 1：網路基本資訊探測
        * Layer 2：Wi-Fi 安全資訊探測
        * Layer 3：區域網路裝置掃描 (Nmap)
        * Layer 4：路由器特定探測
    * 3.2 風險分析維度
4. 報告產出格式
    * 4.1 報告結構
    * 4.2 報告範例
    * 4.3 Q&A 互動模式
5. 技術堆疊與開發環境
    * 5.1 核心技術堆疊
    * 5.2 開發環境需求
6. 實作時程與分工規劃
    * 6.1 Milestone 時程表
7. 倫理考量與限制
    * 7.1 倫理與法律考量
    * 7.2 系統限制
8. 參考文獻
    * 8.1 漏洞資料庫與安全框架
    * 8.2 技術工具與框架
    * 8.3 學術論文與相關研究

---

## 1. 專案概述

### 1.1 研究背景與動機
隨著智慧家庭與物聯網 (IoT) 裝置的普及，一般家庭網路已經從過去僅有電腦和手機的簡單環境，轉變為包含 IP Camera、智慧音箱、掃地機器人、智慧電視等多種裝置的複雜網路。然而，大多數使用者缺乏資安專業知識，導致這些裝置經常以預設密碼、過時韌體、開放不必要的端口等不安全狀態運作。

本專案旨在開發一套基於大型語言模型 (LLM) 的自動化家庭網路資安健檢系統。系統透過 Agent 架構自動執行網路掃描、裝置辨識、漏洞比對與風險分析，最終產出一般人也看得懂的資安健檢報告，並提供自然語言問答介面讓使用者能深入詢問細節。

### 1.2 專案目標
* **自動化探測**：Agent 自動掃描區域網路，發現所有連線裝置、開放端口、服務版本與作業系統資訊。
* **智慧分析**：結合 RAG (Retrieval-Augmented Generation) 架構比對 CVE 漏洞資料庫，對掃描結果進行多維度風險評估。
* **報告產生**：自動產出結構化的資安健檢報告，包含風險評分、各裝置風險說明、優先修復建議。
* **互動問答**：使用者可用自然語言追問任何掃描結果的細節，獲得深入的資安建議。

### 1.3 預期成果
* 提供一個非技術人員也能使用的家庭網路資安工具，降低資安門檻。
* 展示 LLM Agent 在資安領域的實際應用潛力，特別是自動化工具呼叫與結果推理。
* 驗證 RAG 架構在漏洞比對與安全建議場景中的有效性。

---

## 2. 系統架構設計

### 2.1 整體架構總覽
本系統採用分層式架構，共分為四個主要層次：前端使用者介面、LLM Agent 核心層、工具執行層、以及知識庫層。各層之間透過結構化資料傳遞 (JSON) 進行溝通。

#### 2.1.1 架構圖說明
系統運作流程如下：

| 《 系統架構流程圖 》 | ↓ |
| :--- | :--- |
| **[前端介面]** Streamlit Chat UI | 使用者輸入「開始掃描」 |
| **[LLM Agent 核心]** LangChain Tool-Calling Agent | Agent 自動決定執行順序 |
| **[工具執行層]** Nmap / nmcli / HTTP Probe | 原始掃描資料 |
| **[知識庫層]** RAG + CVE/NVD + OWASP IoT Top 10 | 比對結果 |
| **[輸出]** 資安健檢報告 + Q&A 互動模式 | |

### 2.2 模組詳細設計

#### 模組一：前端使用者介面
* **技術選型**： 採用 Streamlit 建立對話式聊天介面，提供使用者友善的互動體驗。使用者僅需點擊「開始掃描」按鈕即可啟動全自動掃描流程，掃描完成後可以自然語言追問問題。
* **主要功能**：
    * 即時顯示掃描進度（各工具執行狀態）。
    * 報告產出後以視覺化方式呈現各裝置風險。
    * 支援自然語言 Q&A 追問模式。

#### 模組二：LLM Agent 核心層
* **技術選型**： 使用 LangChain 的 Tool-Calling Agent 架構，讓 LLM 自主決定要呼叫哪些掃描工具、以什麼順序執行、以及如何綜合分析結果。
* **Agent 工作流程**：
    1. 接收使用者指令。
    2. 呼叫 `get_wifi_security` 取得 Wi-Fi 加密資訊。
    3. 呼叫 `scan_network` 執行區域網路裝置掃描。
    4. 呼叫 `check_router_info` 探測路由器型號與韌體資訊。
    5. 對每個裝置呼叫 `lookup_cve` 查詢已知漏洞。
    6. 呼叫 `check_open_ports_risk` 分析開放端口風險。
    7. 綜合所有資料產出健檢報告。

#### 模組三：工具執行層
Agent 可呼叫的工具清單如下：

| 工具名稱 | 技術實作 | 取得資訊 |
| :--- | :--- | :--- |
| `get_network_info` | psutil + ip route | 本機 IP、子網路、預設閘道、DNS 設定 |
| `get_wifi_security` | nmcli / iwconfig | Wi-Fi SSID、加密方式 (WPA2/WPA3)、訊號強度 |
| `scan_network` | python-nmap | 區網內所有裝置、開放 Port、服務版本、OS 辨識 |
| `check_router_info` | HTTP requests | 路由器型號、管理介面狀態、Server Header |
| `lookup_cve` | RAG 向量查詢 | 特定裝置型號的已知 CVE 漏洞 |
| `check_open_ports_risk` | RAG + LLM 推理 | 各開放 Port/服務的安全風險分析 |

#### 模組四：RAG 知識庫層
* **技術選型**： 使用 ChromaDB 或 FAISS 作為向量資料庫，使用 Azure OpenAI 的 text-embedding-3-small 進行文件 embedding（採用多語言模型以支援中英文混合查詢）。
* **知識庫資料來源**：
    * NVD (National Vulnerability Database) API 2.0 — 透過 REST API 查詢路由器、IoT 相關 CVE。
    * OWASP IoT Top 10 — IoT 裝置常見攻擊面與防禦建議。
    * CIS Benchmark for Home Routers — 家用路由器安全設定最佳實踐。
    * NIST SP 800-183 — IoT 網路安全指南。
    * 各大路由器廠牌已知弱點整理文件（TP-Link, Netgear, D-Link, ASUS 等）。

---

## 3. 掃描內容與分析維度

### 3.1 自動掃描蒐集內容
系統的自動化掃描分為四個層次，逐步深入探測網路環境：

* **Layer 1：網路基本資訊探測**
  使用 Python 內建模組（psutil、socket）與系統指令取得本機網路組態：
    * 本機 IP 位址與子網路遮罩
    * 預設閘道（路由器 IP）
    * DNS 伺服器設定
    * 網路介面狀態（有線/無線）

* **Layer 2：Wi-Fi 安全資訊探測**
  透過 nmcli 或 iwconfig 取得無線網路的安全組態：
    * 目前連接的 SSID
    * 加密方式（WPA3-Personal / WPA2-PSK / WPA / WEP / Open）
    * 訊號強度與頻段（2.4GHz / 5GHz）
    * 是否存在隱藏 SSID

* **Layer 3：區域網路裝置掃描 (Nmap)**
  使用 python-nmap 執行完整的區域網路掃描，這是系統最核心的掃描步驟：
    * 主機探索 (Host Discovery)：探測子網路內所有活躍裝置
    * 端口掃描 (Port Scanning)：掃描 Top 100 常用端口的開放狀態
    * 服務偵測 (Service Detection, -sV)：識別各端口執行的服務名稱與版本
    * 作業系統識別 (OS Detection, -O)：推測裝置的作業系統類型
    * MAC Address 擷取：用於識別裝置廠牌（OUI Lookup）

* **Layer 4：路由器特定探測**
  針對預設閘道 (Gateway IP) 進行深入探測：
    * 嘗試存取 HTTP/HTTPS 管理介面，分析回應中的 Server Header 和 HTML Title
    * 檢查是否開啟 UPnP (Port 1900)
    * 檢查是否開啟 Telnet (Port 23) 或 SSH (Port 22) 遠端管理
    * 檢查 DNS Rebinding 保護狀態

### 3.2 風險分析維度
Agent 將從以下五個維度進行綜合風險評估：

| 評估維度 | 評估內容 | 評分方式 | 判定基準 |
| :--- | :--- | :--- | :--- |
| 路由器漏洞 | 型號是否有未修補的已知 CVE | 高/中/低 | 比對 NVD 資料庫、CVSS 評分 |
| 加密協定 | Wi-Fi 加密等級 | 高/中/低 | WPA3 > WPA2 > WPA > WEP > Open |
| IoT 暴露面 | 各 IoT 裝置的攻擊面分析 | 高/中/低 | OWASP IoT Top 10 對照 |
| 網路隔離 | 訪客網路、IoT 網段分離狀態 | 有/無 | 子網路劃分與裝置分佈 |
| 遠端攻擊面 | 遠端管理、UPnP、外部可存取服務 | 高/中/低 | 暴露於外網的服務數量 |

---

## 4. 報告產出格式

### 4.1 報告結構
系統產出的資安健檢報告包含以下欄位：
* **網路環境摘要**：網路拓撲、裝置清單、基本組態資訊。
* **總體風險評分**：A（安全）到 F（危險）的等級評分。
* **逐裝置風險分析**：每個裝置的開放端口、已知漏洞、風險等級。
* **各維度風險詳述**：五個評估維度的分項說明。
* **優先修復建議**：按緊迫性排序的具體修復步驟。

### 4.2 報告範例
以下為系統產出報告的範例片段：

> **家庭網路資安健檢報告**
> **總體風險評分**：C（需要改善）
> **發現裝置**：7 台 | 高風險：2 項 | 中風險：3 項 | 低風險：1 項
>
> 🔴 **高風險項目**：
> 1. IP Camera (192.168.1.101, Hikvision) 開放 RTSP Port 554 且無加密，可能被遠端存取監控畫面。
> 2. 路由器 TP-Link Archer AX73 存在 2 個未修補的 CVE (CVE-2023-XXXXX, CVSS 8.1)。
> 
> 🟡 **中風險項目**：
> 1. Wi-Fi 使用 WPA2 而非 WPA3，建議升級。
> 2. 未偵測到訪客網路隔離，IoT 裝置與主要裝置同網段。
> 3. UPnP 服務已啟用 (Port 1900)，可能被利用為攻擊入口。

### 4.3 Q&A 互動模式
報告產出後，系統自動進入 Q&A 模式。使用者可以用自然語言提問，例如：
* 「那台 IP Camera 具體有什麼風險？」
* 「我該怎麼更新路由器韌體？」
* 「怎樣把 IoT 裝置和主網路隔離？」

Agent 將根據先前的掃描結果與 RAG 知識庫來回答，提供具體且個人化的資安建議。

---

## 5. 技術堆疊與開發環境

### 5.1 核心技術堆疊

| 層次 | 技術 | 說明 |
| :--- | :--- | :--- |
| 程式語言 | Python 3.10+ | 主要開發語言 |
| LLM | Azure OpenAI | 核心推理引擎 |
| Agent 框架 | LangChain | Tool-Calling Agent 架構 |
| 向量資料庫 | ChromaDB / FAISS | RAG 知識庫儲存與查詢 |
| Embedding | Azure OpenAI Embeddings | 使用 text-embedding-3-small |
| 網路掃描 | Nmap + python-nmap | 區域網路裝置探測與端口掃描 |
| 前端 | Streamlit | 對話式 Chat UI 與報告呈現 |

### 5.2 開發環境需求
* **作業系統**：Linux (Ubuntu 22.04+) 或 macOS，Nmap 需要 sudo 權限執行 OS 偵測。
* **Python 套件**：langchain, python-nmap, chromadb, streamlit, psutil, requests, openai。
* **外部工具**：Nmap 7.80+, nmcli (NetworkManager)。
* **LLM 推論**：Azure OpenAI API。

---

## 6. 實作時程與分工規劃

### 6.1 Milestone 時程表

| 時間點 | 任務內容 | 交付 |
| :--- | :--- | :--- |
| Week 14 | 專案規劃與環境搭建 | 專案架構確定、開發環境安裝完成 |
| Week 15 | Agent 整合 + Prompt 調校 + 掃描工具原型 + RAG 知識庫建置 | Agent 可自動執行完整掃描流程、報告產出格式確定、Nmap 掃描工具可獨立執行、NVD 資料下載與清洗、知識庫建置完成 |
| Week 16 | 前端整合 + 測試 + 最終報告 | Streamlit UI 完成、多情境測試、最終團隊報告繳交 |

**分工規劃：**
| 成員 | 負責模組 | 具體任務 |
| :--- | :--- | :--- |
| 陳揚盛 | 掃描工具開發、前端 + 測試 | Nmap 掃描封裝、Wi-Fi 探測、路由器探測工具實作、Streamlit UI 開發、測試情境建立、Demo 準備 |
| 陳俊瑋 | Agent 核心 + Prompt、RAG 知識庫 | LangChain Agent 架構、System Prompt 設計、報告產生邏輯、NVD 資料清洗、文件切塊、向量資料庫建置與查詢測試 |

---

## 7. 倫理考量與限制

### 7.1 倫理與法律考量
* **授權原則**：系統僅能在使用者明確授權下掃描其自己的網路，不得用於掃描他人網路。
* **資料隱私**：系統透過 Azure OpenAI API 進行 LLM 推理，傳送之資料為區域網路內部掃描結果（私有 IP、端口狀態、裝置型號等），不含個人身分資訊或機敏資料。Azure OpenAI 承諾不將客戶資料用於模型訓練，符合企業級資料處理規範。
* **責任聲明**：系統產出的報告僅供參考，不構成專業資安稽核服務。

### 7.2 系統限制
* 掃描範圍限於區域網路（LAN），無法評估外網攻擊面。
* Nmap OS 偵測可能不準確，特別是對於 IoT 裝置。
* 路由器型號辨識依賴 HTTP Banner，不是所有路由器都會暴露此資訊。
* CVE 比對依賴知識庫的完整性與更新頻率。
* LLM 可能產生幻覺，需要人工驗證關鍵建議。

---

## 8. 參考文獻

### 8.1 漏洞資料庫與安全框架
* NIST National Vulnerability Database (NVD). https://nvd.nist.gov/ — CVE 漏洞資料主要來源，提供 CVSS 評分與漏洞詳細資訊。
* OWASP IoT Top 10 (2018，目前最新正式發布版). https://owasp.org/www-project-internet-of-things/ — IoT 裝置十大安全風險清單。
* CIS Benchmarks for Consumer-Grade Routers. https://www.cisecurity.org/benchmark — 家用路由器安全設定最佳實踐指南。
* NIST SP 800-183: Networks of Things. https://csrc.nist.gov/publications/detail/sp/800-183/final — IoT 網路安全架構指南。
* MITRE ATT&CK Framework. https://attack.mitre.org/ — 攻擊技術與戰術知識庫。

### 8.2 技術工具與框架
* LangChain Documentation. https://python.langchain.com/docs/ — LLM Agent 框架技術文件。
* Nmap Reference Guide. https://nmap.org/book/man.html — 網路掃描工具完整指南。
* ChromaDB Documentation. https://docs.trychroma.com/ — 向量資料庫技術文件。
* Streamlit Documentation. https://docs.streamlit.io/ — 前端介面框架技術文件。

### 8.3 學術論文與相關研究
* Lewis, P. et al. (2020). "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks." *Advances in Neural Information Processing Systems (NeurIPS)*. — RAG 架構原始論文。
* Yao, S. et al. (2023). "ReAct: Synergizing Reasoning and Acting in Language Models." *International Conference on Learning Representations (ICLR)*. — LLM Agent 推理與行動架構。
* Happe, A. & Cito, J. (2023). "Getting pwn'd by AI: Penetration Testing with Large Language Models." *ACM Joint European Software Engineering Conference*. — LLM 在滲透測試中的應用。
* Motlagh, F. N. et al. (2024). "Large Language Models in Cybersecurity: State-of-the-Art." *arXiv preprint*. — LLM 在資安領域的全面回顧。