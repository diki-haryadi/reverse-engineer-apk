# Panduan Reverse Engineering APK dan Network Monitoring

## Daftar Isi
- [Reverse Engineering APK](#reverse-engineering-apk)
- [Setup APK Decompiler di macOS](#setup-apk-decompiler-di-macos)
- [Menangani APK yang Diobfuscation](#menangani-apk-yang-diobfuscation)
- [Memantau dan Mengambil HTTP Requests](#memantau-dan-mengambil-http-requests-dari-aplikasi-mobile)
- [Memantau Protokol Non-HTTP dengan Wireshark](#memantau-protokol-non-http-dengan-wireshark-step-by-step)

## Reverse Engineering APK

### Q: Bagaimana reverse engineer file APK jadi code?

Untuk melakukan reverse engineering file APK menjadi code, ada beberapa langkah dan tools yang bisa digunakan:

#### Tools yang Dibutuhkan

1. **APK Decompiler** seperti:
   - Jadx
   - Apktool
   - dex2jar + JD-GUI

#### Langkah-Langkah Dasar

1. **Ekstrak APK**
   - APK sebenarnya adalah file ZIP dengan ekstensi .apk
   - Anda bisa merubah ekstensinya ke .zip dan mengekstraknya

2. **Decompile menggunakan Apktool**
   - Untuk mendapatkan resources, AndroidManifest.xml, dan smali code
   ```
   apktool d nama_aplikasi.apk -o output_folder
   ```

3. **Menggunakan dex2jar untuk mengkonversi DEX ke JAR**
   - DEX (Dalvik Executable) adalah format bytecode Android
   - Konversi ke JAR untuk melihat kode Java
   ```
   d2j-dex2jar.bat nama_aplikasi.apk
   ```

4. **Gunakan JD-GUI untuk melihat kode Java**
   - Buka file JAR hasil konversi dengan JD-GUI

5. **Alternatif: Gunakan Jadx (cara termudah)**
   - Jadx bisa langsung mengkonversi APK ke Java source code
   ```
   jadx-gui nama_aplikasi.apk
   ```

#### Catatan Penting

- Reverse engineering APK dapat melanggar hukum jika digunakan untuk tujuan ilegal
- Aplikasi terproteksi mungkin menggunakan teknik anti-reverse engineering
- Beberapa aplikasi menggunakan obfuscator (seperti ProGuard) yang membuat kode hasil decompile sulit dibaca

## Setup APK Decompiler di macOS

### Q: Bagaimana setup APK Decompiler seperti Jadx, Apktool, dex2jar + JD-GUI di macOS?

Berikut cara setup tools untuk reverse engineering APK di macOS:

#### 1. Setup Jadx

Jadx adalah tool all-in-one yang paling mudah digunakan untuk decompile APK.

```bash
# Menggunakan Homebrew
brew install jadx

# Menjalankan GUI
jadx-gui

# Atau command line
jadx nama_aplikasi.apk -d output_folder
```

#### 2. Setup Apktool

```bash
# Menggunakan Homebrew
brew install apktool

# Alternatif, download manual:
# 1. Download wrapper script: https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/osx/apktool
# 2. Download apktool jar: https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar
# 3. Rename jar ke apktool.jar
# 4. Pindahkan keduanya ke /usr/local/bin/
# 5. Set permission:
chmod +x /usr/local/bin/apktool
chmod +x /usr/local/bin/apktool.jar
```

#### 3. Setup dex2jar + JD-GUI

```bash
# Menggunakan Homebrew (untuk dex2jar)
brew install dex2jar

# Download JD-GUI:
# 1. Kunjungi: https://github.com/java-decompiler/jd-gui/releases
# 2. Download file .dmg untuk macOS
# 3. Install seperti aplikasi macOS lainnya dengan drag ke Applications folder
```

#### Penggunaan Dasar

1. **Jadx** (paling mudah):
   ```bash
   jadx-gui nama_aplikasi.apk
   # Atau untuk CLI:
   jadx nama_aplikasi.apk -d output_folder
   ```

2. **Apktool** (untuk resources dan smali code):
   ```bash
   apktool d nama_aplikasi.apk -o output_folder
   ```

3. **dex2jar + JD-GUI**:
   ```bash
   # Konversi APK ke JAR
   d2j-dex2jar nama_aplikasi.apk
   
   # Buka JD-GUI dari Applications
   # Drag file hasil konversi (biasanya nama_aplikasi-dex2jar.jar) ke JD-GUI
   ```

#### Tips Tambahan

- Pastikan Java terinstall di sistem Anda (`java --version`)
- Jika menggunakan macOS versi terbaru, Anda mungkin perlu mengonfirmasi security warning saat menjalankan tools
- Beberapa tools mungkin memerlukan akses admin, gunakan `sudo` jika diperlukan

## Menangani APK yang Diobfuscation

### Q: Bagaimana jika APK di-obfuscation?

Ketika berhadapan dengan APK yang diobfuscation (dikaburkan), proses reverse engineering menjadi lebih kompleks. Berikut cara mengatasinya:

#### Jenis-Jenis Obfuscation dan Solusinya

##### 1. Obfuscation Nama (Renaming)
- **Gejala**: Nama kelas, metode, dan variabel diganti dengan a, b, c, atau a1, a2, a3, dll.
- **Pendekatan**:
  - Analisis alur program berdasarkan fungsi, bukan nama
  - Lacak string literals yang tidak diobfuscate
  - Perhatikan AndroidManifest.xml untuk entry points

##### 2. Perlindungan DEX
- **Gejala**: Aplikasi gagal di-decompile atau menghasilkan kode yang rusak
- **Solusi**:
  ```bash
  # Gunakan opsi yang lebih kuat di jadx
  jadx --deobf --show-bad-code nama_aplikasi.apk
  ```

##### 3. Packing & Encryption
- **Gejala**: Aplikasi mendekrip atau memuat kode saat runtime
- **Pendekatan**:
  - Gunakan dynamic analysis (debugging runtime)
  - Pakai Frida untuk meng-hook fungsi decryption
  ```bash
  # Install Frida
  pip install frida-tools
  ```

##### 4. Anti-Tampering 
- **Pendekatan**: Gunakan emulator atau perangkat yang di-root dengan Magisk + modules untuk menyembunyikan root

#### Tools Tambahan untuk Mengatasi Obfuscation

1. **BytecodeDiffuser**
   - Membandingkan versi APK sebelum dan sesudah untuk menemukan perubahan

2. **Androguard**
   ```bash
   # Install dengan pip
   pip install androguard
   
   # Analisis APK
   androguard analyze -d nama_aplikasi.apk
   ```

3. **MobSF (Mobile Security Framework)**
   ```bash
   # Install dengan Docker
   docker pull opensecurity/mobile-security-framework-mobsf
   docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
   ```

#### Teknik Analisis

1. **Identifikasi Pola**
   - Cari string constants untuk menemukan fungsi penting
   - Perhatikan API calls ke system services

2. **Fokus pada Native Libraries**
   - Periksa folder lib/ untuk file .so yang bisa berisi logika utama
   - Gunakan tools seperti Ghidra untuk menganalisis native code

3. **Debugging Runtime**
   - Setup Android Studio dengan konfigurasi debugging
   - Connect ke aplikasi berjalan menggunakan adb dan JDWP

```bash
# Melihat proses berjalan
adb shell ps | grep nama_package

# Attach debugger
adb forward tcp:8700 jdwp:[PID]
jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8700
```

Reverse engineering APK yang diobfuscate adalah proses iteratif dan membutuhkan kesabaran. Kombinasikan analisis statis (melihat kode) dan dinamis (observasi runtime) untuk mendapatkan hasil terbaik.

## Memantau dan Mengambil HTTP Requests dari Aplikasi Mobile

### Q: Bagaimana cara untuk listen request HTTP dari aplikasi dan mengambil curl dari setiap request ke internet?

Untuk melakukan intercept dan mengambil curl dari request HTTP yang dikirim oleh aplikasi mobile, Anda dapat menggunakan beberapa metode berikut:

#### 1. Menggunakan Proxy seperti Charles atau Proxyman

##### Setup di macOS:
```bash
# Install Charles Proxy via Homebrew
brew install --cask charles

# Atau install Proxyman
brew install --cask proxyman
```

##### Langkah-langkah:
1. Jalankan Charles/Proxyman di Mac
2. Konfigurasi proxy di perangkat Android:
   - Settings → Wi-Fi → Tekan lama koneksi Wi-Fi → Modify network
   - Aktifkan Advanced options
   - Ubah Proxy ke Manual
   - Masukkan IP Mac Anda dan port (biasanya 8888)
3. Install sertifikat SSL di perangkat:
   - Di Charles: Help → SSL Proxying → Install Charles Root Certificate on Mobile
   - Buka browser di Android dan akses: chls.pro/ssl
   - Install sertifikat dari Settings → Security → Install from storage

#### 2. Menggunakan mitmproxy (Command-line)

```bash
# Install via Homebrew
brew install mitmproxy

# Jalankan
mitmproxy

# Untuk mengekspor sebagai curl commands
mitmproxy -s ./scripts/export_to_curl.py
```

##### Script export_to_curl.py:
```python
import json
import re
from mitmproxy import http
import subprocess

def request(flow: http.HTTPFlow) -> None:
    cmd = ["curl", "-X", flow.request.method, flow.request.url]
    
    # Add headers
    for k, v in flow.request.headers.items():
        cmd.extend(["-H", f"{k}: {v}"])
    
    # Add request body if present
    if flow.request.content:
        cmd.extend(["--data-binary", flow.request.content.decode(errors='replace')])
    
    # Print the curl command
    print(" ".join([re.sub(r"(['])", r"\\\1", x) for x in cmd]))
```

#### 3. Menggunakan Frida untuk Intercept dari Dalam Aplikasi

Frida adalah tool yang powerful untuk dynamic analysis.

```bash
# Install Frida
pip install frida-tools

# Install Frida server pada perangkat Android yang sudah di-root
# Download dari: https://github.com/frida/frida/releases
```

##### Contoh script Frida (save sebagai intercept_http.js):
```javascript
Java.perform(function() {
    // Intercept OkHttp
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(request) {
        console.log("[+] Intercepted OkHttp request:");
        console.log("URL: " + request.url().toString());
        console.log("Method: " + request.method());
        
        // Build curl command
        var curlCmd = "curl -X " + request.method() + " '" + request.url().toString() + "'";
        
        // Add headers
        var headers = request.headers();
        for (var i = 0; i < headers.size(); i++) {
            curlCmd += " -H '" + headers.name(i) + ": " + headers.value(i) + "'";
        }
        
        // Add body if present
        var body = request.body();
        if (body) {
            var Buffer = Java.use('okio.Buffer');
            var buffer = Buffer.$new();
            body.writeTo(buffer);
            curlCmd += " --data-binary '" + buffer.readUtf8() + "'";
        }
        
        console.log("CURL: " + curlCmd);
        return this.newCall(request);
    };
});
```

```bash
# Jalankan Frida
frida -U -l intercept_http.js -f com.target.app --no-pause
```

#### 4. Menggunakan Burp Suite

```bash
# Install via Homebrew
brew install --cask burpsuite

# Konfigurasi sama seperti Charles Proxy
# Untuk mengambil curl, klik kanan pada request dan pilih "Copy as curl command"
```

#### Catatan Penting

1. Untuk aplikasi yang menggunakan certificate pinning, Anda perlu:
   - Menggunakan Frida untuk bypass certificate pinning
   - Menggunakan objection tool: `objection --gadget com.package.name explore --startup-command "android sslpinning disable"`

2. Untuk aplikasi yang berjalan di emulator:
   - Gunakan `adb reverse tcp:8888 tcp:8888` untuk mengatur port forwarding

3. Untuk aplikasi yang menggunakan protokol non-HTTP:
   - Pertimbangkan menggunakan Wireshark untuk network capture lebih luas

## Memantau Protokol Non-HTTP dengan Wireshark (Step-by-Step)

### Q: Beritahukan step by step caranya untuk aplikasi yang menggunakan protokol non-HTTP menggunakan Wireshark

#### Persiapan

1. **Install Wireshark di macOS**
   ```bash
   brew install --cask wireshark
   ```

2. **Install dependensi tambahan jika diperlukan**
   ```bash
   brew install libpcap
   ```

#### Langkah-Langkah Dasar

##### 1. Setup Wireshark
1. Buka Wireshark dari Applications
2. Berikan izin administratif jika diminta

##### 2. Konfigurasi Capture Interface
1. Di layar utama Wireshark, Anda akan melihat daftar interface jaringan
2. Pilih interface yang digunakan perangkat Android:
   - Untuk Wi-Fi: Pilih antarmuka Wi-Fi (en0 biasanya)
   - Untuk USB tethering: Pilih interface yang muncul saat tethering diaktifkan

##### 3. Buat Filter Khusus
1. Di kolom filter di bagian atas, masukkan filter untuk mengidentifikasi traffic dari perangkat Android:
   ```
   ip.addr == [IP perangkat Android]
   ```
2. Untuk mendapatkan IP perangkat Android:
   ```bash
   adb shell ip addr show wlan0
   ```

##### 4. Mulai Capture
1. Klik tombol "Start Capturing Packets" (ikon hiu di toolbar)
2. Jalankan aplikasi di perangkat Android
3. Lakukan aktivitas yang ingin Anda pantau

##### 5. Analisis Traffic
1. Klik "Stop Capturing Packets" setelah selesai
2. Telusuri paket yang tertangkap
3. Gunakan filter tambahan untuk mempersempit hasil:
   ```
   # Untuk melihat traffic TCP
   tcp
   
   # Untuk port tertentu
   tcp.port == 443
   
   # Untuk SSL/TLS traffic
   ssl
   ```

#### Teknik Lanjutan

##### 1. Dekripsi SSL/TLS (HTTPS) Traffic
1. Konfigurasi Wireshark untuk menggunakan kunci SSL:
   - Buka Preferences (Edit > Preferences)
   - Navigate ke Protocols > TLS
   - Tambahkan "(Pre)-Master-Secret log filename" yang menunjuk ke file SSLKEYLOGFILE

2. Konfigurasi variabel lingkungan di perangkat Android (memerlukan root):
   ```bash
   adb shell "su -c 'setprop log.tag.SSLKEYLOGFILE /data/local/tmp/sslkey.log'"
   ```

3. Untuk aplikasi yang menggunakan Chrome WebView:
   ```bash
   adb shell "su -c 'setprop debug.com.android.webview.SSLKEYLOGFILE /data/local/tmp/sslkey.log'"
   ```

##### 2. Setup Capture pada Jaringan Mobile

1. Untuk perangkat yang menggunakan koneksi mobile (bukan Wi-Fi):
   - Aktifkan USB tethering dari perangkat ke Mac
   - Di Wireshark, pilih interface yang muncul saat tethering diaktifkan

2. Alternatif menggunakan hotspot:
   - Aktifkan hotspot di Android
   - Hubungkan Mac ke hotspot tersebut
   - Capture pada interface Wi-Fi Mac

##### 3. Mendapatkan Informasi TCP/UDP Lengkap

1. Klik kanan pada paket > Follow > TCP/UDP Stream
2. Ini akan menampilkan semua data yang dikirim dalam koneksi yang sama
3. Untuk mengekspor:
   - Klik "Save As" pada jendela Stream
   - Pilih format Raw atau ASCII

##### 4. Memantau aplikasi tertentu menggunakan pid-owner (Android rooted)

1. Dapatkan PID aplikasi target:
   ```bash
   adb shell ps | grep com.nama.paket
   ```

2. Di perangkat Android yang sudah di-root:
   ```bash
   adb shell "su -c 'iptables -t mangle -A OUTPUT -p all -m owner --pid-owner [PID] -j MARK --set-mark 1'"
   ```

3. Capture paket dengan filter:
   ```
   ip.addr == [IP Android] && ip.dsfield.dscp == 1
   ```

#### Mengekstrak Command dari Capture

Untuk mengubah traffic tertangkap menjadi format perintah curl:

1. Klik kanan pada paket HTTP > Follow > HTTP Stream
2. Copy seluruh request header dan body

3. Gunakan tool tshark (command-line Wireshark) untuk otomatisasi:
   ```bash
   tshark -r capture.pcapng -Y "http.request" -T fields -e http.request.method -e http.request.uri -e http.file_data
   ```

4. Untuk protokol non-HTTP, ekstrak request dan response dalam format raw:
   ```bash
   tshark -r capture.pcapng -Y "tcp.port == 8080" -T fields -e data
   ```

Metode ini memungkinkan Anda memantau traffic aplikasi bahkan jika menggunakan protokol custom atau binary.
