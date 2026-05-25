# Sni-spoof-windows
Professional SNI Spoofing Tool for Windows - Bypass internet censorship by manipulating TLS SNI field using WinDivert. GUI included.


<div align="center">
  

  <h1>🛡️ Medad SNI Spoofer</h1>
  <h3>Professional SNI Spoofing Tool for Windows</h3>
  <h4>✨ Bypass Internet Censorship | Easy to Use | Open Source ✨</h4>

  <br/>

  <a href="https://github.com/medadvpn/Sni-spoof-windows/releases/latest">
    <img src="https://img.shields.io/badge/Download-Latest_Release-brightgreen?style=for-the-badge&logo=github" alt="Download">
  </a>
  
  <a href="https://t.me/medad_Vpn">
    <img src="https://img.shields.io/badge/Telegram-Join_Channel-blue?style=for-the-badge&logo=telegram" alt="Telegram">
  </a>

  <br/>

  <img src="https://img.shields.io/badge/Platform-Windows_10%2F11-0078d7?style=flat-square&logo=windows">
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776ab?style=flat-square&logo=python">
  <img src="https://img.shields.io/badge/License-Open%20Source-green?style=flat-square">
  <img src="https://img.shields.io/badge/PyQt6-GUI-41cd52?style=flat-square">

</div>

---

## 📖 Table of Contents / فهرست مطالب

- [🇬🇧 English Documentation](#-english-documentation)
- [🇮🇷 مستندات فارسی](#-مستندات-فارسی)
- [📦 Download & Installation](#-download--installation)
- [🖱️ How to Use](#️-how-to-use)
- [🤝 Support & Donation](#-support--donation)

---

## 🇬🇧 English Documentation

### 🔍 What is Medad SNI Spoofer?

**Medad SNI Spoofer** is a professional Windows tool based on the **SNI-Spoofing** technique.  
It allows you to bypass network censorship by manipulating the **TLS SNI (Server Name Indication)** field of HTTPS traffic.

The tool uses **WinDivert** to capture, modify, and inject packets in real-time using the `wrong_seq` method.

> ⚠️ **Educational Purpose Only** – Use responsibly and in compliance with local laws.

### ✨ Features

| Feature | Description |
|---------|-------------|
| 🖥️ **Modern GUI** | Built with PyQt6 – Dark theme, easy to use |
| 🔄 **Real-time Packet Injection** | Uses WinDivert for low-level packet manipulation |
| 🎭 **Custom Fake SNI** | Set any SNI (e.g., `www.google.com`, `www.hcaptcha.com`) |
| 🌐 **Auto Interface Detection** | Automatically detects your default IPv4 address |
| 📋 **Live Log Viewer** | See all connections and packets in real-time |
| ⚡ **One-Click Connect** | Simple toggle button with power icon |
| 🧩 **Portable** | Can be used as standalone `.exe` |
| 🔧 **Configurable** | Save/Load settings via `config.json` |


1. The tool creates a local proxy (default `127.0.0.1:40443`)
2. When a TLS ClientHello is detected, the **SNI** is replaced with a fake one
3. The modified packet is injected using the **wrong_seq** bypass method
4. The target server responds normally, and the connection is relayed

---

## 🇮🇷 مستندات فارسی

### 🔍 ابزار مداد اس‌ان‌آی اسپوفینگ چیست؟

**مداد اس‌ان‌آی اسپوفینگ** یک ابزار حرفه‌ای ویندوزی بر اساس تکنیک **SNI-Spoofing** است که به شما کمک می‌کند فیلترینگ شبکه را با دستکاری فیلد **SNI** در ترافیک TLS دور بزنید.

> ⚠️ **فقط برای اهداف آموزشی** – استفاده مسئولانه و مطابق با قوانین کشور الزامی است.

### ✨ قابلیت‌ها

| قابلیت | توضیح |
|--------|-------|
| 🖥️ **رابط گرافیکی مدرن** | ساخته شده با PyQt6 – تم دارک و کاربردی |
| 🔄 **تزریق لحظه‌ای پکت** | استفاده از WinDivert برای تغییر پکت‌ها |
| 🎭 **SNI جعلی دلخواه** | قابلیت تنظیم هر SNI دلخواه |
| 🌐 **تشخیص خودکار آی‌پی** | تشخیص خودکار آی‌پی اینترفیس شبکه |
| 📋 **نمایش زنده لاگ‌ها** | مشاهده تمام اتصالات و پکت‌ها |
| ⚡ **اتصال یک‌کلیک** | دکمه شیک با آیکون پاور |
| 🧩 **قابل حمل** | قابلیت اجرا به صورت فایل `.exe` مستقل |
| 🔧 **قابل تنظیم** | ذخیره/بارگذاری تنظیمات با فایل `config.json` |



## 📦 Download & Installation

### 🔽 Download Latest Release

👉 **[Click here to download the latest version](https://github.com/medadvpn/Sni-spoof-windows/releases/latest)**

> Choose the installer (`.exe`) or portable version.

### ⚙️ Installation Steps

1. **Download** the installer from the [Releases](https://github.com/medadvpn/Sni-spoof-windows/releases/latest) page
2. **Run as Administrator** (Right-click → "Run as administrator")
3. Follow the installation wizard
4. Launch **Medad SNI Spoofer** from desktop shortcut

### 🐍 Run from Source (for developers)

```bash
# Clone the repository
git clone https://github.com/medadvpn/Sni-spoof-windows.git
cd Sni-spoof-windows

# Install requirements
pip install -r requirements.txt

# Run the tool (as Administrator)
python medad_sni_spoofer.py
```

### 📋 Requirements

- Windows 10 / Windows 11
- Administrator privileges
- Python 3.9+ (only for source run)

---

## 🖱️ How to Use

### Quick Start Guide

| Step | Action |
|------|--------|
| 1 | Open the application **as Administrator** |
| 2 | Go to the **Config** tab |
| 3 | Set your **Fake SNI** (e.g., `www.hcaptcha.com`) |
| 4 | Set **Destination IP & Port** (e.g., `104.19.229.21:443`) |
| 5 | Set **Local Port** (default `40443`) |
| 6 | Click **Save Configuration** |
| 7 | Go to the **Connect** tab |
| 8 | Press **⚡ CONNECT** button |
| 9 | Configure your browser/system proxy to `127.0.0.1:40443` |
| 10 | 🌐 **Browse freely!** |

### Proxy Configuration Examples

#### 🔷 Firefox (No extension)
- Settings → Network Settings → Manual proxy configuration
- HTTP Proxy: `127.0.0.1` Port: `40443`
- Also use this proxy for HTTPS

#### 🔷 Chrome/Edge (with extension)
- Use **SwitchyOmega** extension
- Create a profile with proxy `127.0.0.1:40443`

#### 🔷 System-wide (Windows)
- Settings → Network & Internet → Proxy
- Manual proxy setup → Use a proxy server
- Address: `127.0.0.1` Port: `40443`

---

## 🤝 Support & Donation

### 💬 Telegram Channel

📢 **Join our Telegram for updates, support, and news:**  
👉 [@MedadVpn](https://t.me/medadVpn)

### 💰 Donate / حمایت مالی

If you find this tool useful, please consider supporting the project:

| Currency | Address |
|----------|---------|
| **USDT (TRC20)** | `TYzaxbaTnVUjTwAPpHLrL5oTQLUpEGWDWo` |

> 🙏 Your support helps us continue development and keep the tool free for everyone.

---

## ❓ FAQ / سوالات متداول

### Q: Why do I need Administrator privileges?
**A:** WinDivert (packet injection engine) requires admin rights to capture and modify network packets.

### Q: Does this tool work on all websites?
**A:** It works on most HTTPS websites, but some may have additional protections (HSTS, certificate pinning).

### Q: Is this a VPN?
**A:** No, this is a **local SNI spoofer/proxy**, not a VPN. It doesn't route your traffic through external servers.

### Q: Can I use this with other VPNs?
**A:** It's better to use it alone, but you can chain it with a VPN if you know what you're doing.

---

## 📜 License

Open Source – Referenced from the original [SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) repository.

---

## 🙏 Credits / قدردانی

- **Original SNI-Spoofing technique** – [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)
- **GUI Framework** – PyQt6
- **Community** – All contributors and testers

---

<div align="center">
  <br/>
  <b>Made with ❤️ by Medad Team – Iran</b>
  <br/>
  <b>🚀 No Censorship, Just Freedom 🚀</b>
  <br/><br/>
  
  <a href="https://github.com/medadvpn/Sni-spoof-windows">
    <img src="https://img.shields.io/github/stars/medadvpn/Sni-spoof-windows?style=social" alt="GitHub stars">
  </a>
  
  <a href="https://github.com/medadvpn/Sni-spoof-windows/fork">
    <img src="https://img.shields.io/github/forks/medadvpn/Sni-spoof-windows?style=social" alt="GitHub forks">
  </a>
  
</div>


