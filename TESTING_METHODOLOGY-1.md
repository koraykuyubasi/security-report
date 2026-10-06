# Android Application Security Assessment — Testing Methodology

A step-by-step playbook for the mobile app security assessments in this workspace.
It covers the full flow: obtaining the APK, decompiling, static protection analysis,
setting up the dynamic environment, bypassing runtime protections with Frida,
intercepting TLS traffic, testing the API surface, and generating the final report.

> **Scope note.** These assessments focus on six runtime self-protection categories —
> **code obfuscation, root detection, emulator detection, debugger detection,
> tampering detection, hook detection** — plus **transport security (certificate
> pinning)**, followed by **non-destructive** API abuse testing. Only safe, read-only
> API tests are performed against production backends (no OTP flooding, no payments,
> no password changes, no deletions).

---

## 0. Environment & Toolchain

| Tool | Location / Version | Purpose |
|------|-------------------|---------|
| `apktool` | `java -jar /home/koray/workspace/tools/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/apktool_2.10.0.jar` | Decode resources + smali (`apktool` not on PATH) |
| `jadx` | `/home/koray/Downloads/jadx-1.5.3.zip` (extract to use) | Decompile DEX → readable Java |
| `frida` (host) | `/home/koray/.local/bin/frida` — **17.10.1** | Dynamic instrumentation |
| `frida-server` | `/data/local/tmp/frida-server` — **17.10.1** (on device) | On-device agent |
| `adb` | `/home/koray/Android/Sdk/platform-tools/adb` | Device control |
| `weasyprint` | `/home/koray/.local/bin/weasyprint` | Render HTML → PDF report |
| Emulator | `emulator-5554`, Android 12, x86_64, **Magisk root** | Test device |
| Proxy CA | `~/.config/httptoolkit/ca.pem` + `ca.key` | MITM leaf-cert signing |

**Emulator notes**
- `su` works via Magisk; **`adb root` does NOT** — always wrap privileged commands in `su -c`.
- x86_64 image with ARM translation (needed for arm64-only native libs).

---

## 1. Obtaining the APK

Apps ship either as a single APK or as a **split / XAPK bundle** (base + config splits).

- **Single APK:** e.g. `otowatt/com.ipitex.otowatt.apk`.
- **Split bundle:** a `base.apk` plus `split_config.*` / `config.*` APKs:
  - `base.apk` — code + resources
  - `config.arm64_v8a.apk` / `config.x86_64.apk` — native libs per ABI
  - `config.<lang>.apk` — localized resources
  - `config.<dpi>.apk` — density resources

Keep all splits together; they are installed as a set (see §4).

---

## 2. Decompiling the APK

### 2.1 apktool (resources, manifest, smali)
Use apktool to decode the manifest, resources and smali (best for protection hunting):

```bash
java -jar /home/koray/workspace/tools/Mobile-Security-Framework-MobSF/mobsf/StaticAnalyzer/tools/apktool_2.10.0.jar \
  d -f -o <app>_apktool <app>/base.apk
```

Output of interest:
- `AndroidManifest.xml` — package, versionCode/Name, min/target SDK, `allowBackup`,
  `debuggable`, `networkSecurityConfig`, exported components.
- `apktool.yml` — SDK versions, framework info.
- `smali/`, `smali_classes2/`, ... — Dalvik bytecode (all DEX files).
- `assets/`, `lib/`, `res/` — configs, native libs, resources.

### 2.2 jadx (readable Java, optional)
For a more readable view of complex logic, decompile to Java:

```bash
jadx -d <app>_jadx <app>/base.apk        # or: jadx-gui for interactive browsing
```

Use jadx for reading, apktool smali for **patching / precise hook targets**.

### 2.3 Framework identification
Determine the app framework early — it dictates where the logic lives:
- **Native (Kotlin/Java):** logic in smali/DEX (5Şarj, Pazarama, OTOWATT, Vodafone).
- **React Native:** JS in `assets/index.android.bundle` (Hermes bytecode) + native modules (Sodexo).
- **Flutter:** logic compiled into `lib/**/libapp.so` (Dart AOT) — smali is mostly glue (DoctorIn).

---

## 3. Static Protection Analysis

Grep the decompiled tree for each protection category. The goal is to determine whether
each control is **PRESENT / ADVISORY / ABSENT** and, critically, whether it is
**enforced** (blocks execution) or merely **telemetry** (reported, e.g. to Crashlytics).

### 3.1 Code Obfuscation
- Look for R8/ProGuard renaming: short class names (`Aa/g`, `Pi1`, `kG1`), collapsed packages.
- App-namespace classes partially readable ⇒ partial obfuscation.

### 3.2 Root Detection
```bash
grep -rniE "test-keys|/system/xbin/su|Superuser\.apk|magisk|busybox|RootBeer|JailMonkey" <app>_apktool/
```
- Classic probes: `Build.TAGS` contains `test-keys`; `File.exists()` on `su` paths;
  `Runtime.exec("which su")`.
- **Enforcement check:** trace the boolean result.
  - If it feeds a **dialog / `finish()` / request block** ⇒ **enforced**.
  - If it only populates a Crashlytics/analytics payload ⇒ **telemetry, NOT enforced**
    (e.g. 5Şarj `Aa/g.smali` → Firebase Crashlytics).
  - If it shows a **non-blocking, dismissible dialog** ⇒ **ADVISORY** (e.g. Pazarama
    `SplashFragment.checkDeviceRoot()` → "Devam").

### 3.3 Emulator Detection
```bash
grep -rniE "goldfish|ranchu|vbox|genymotion|sdk_gphone|generic|isEmulator" <app>_apktool/
```
- React Native: `RNDeviceModule.isEmulatorSync()` checks `Build.FINGERPRINT/MODEL/HARDWARE/PRODUCT`.
- Distinguish app-enforced checks from SDK-only ones (Ads/Crashlytics).

### 3.4 Debugger Detection
```bash
grep -rniE "isDebuggerConnected|waitingForDebugger|Debug;->|TracerPid" <app>_apktool/
```
- Usually only Crashlytics telemetry; rarely an enforced ptrace/self-attach.

### 3.5 Hook / Frida Detection
```bash
grep -rniE "frida|xposed|substrate|/proc/self/maps|27042|LSPosed" <app>_apktool/
```
- Look for port scans (27042), `/proc/self/maps` scans, Xposed/Substrate class probes.

### 3.6 Tampering / Integrity
```bash
grep -rniE "getPackageInfo|signatures|PLAY_INTEGRITY|SafetyNet|checkSignature|PAIRIP" <app>_apktool/
```
- APK signature / DEX hash checks, Play Integrity / SafetyNet, PAIRIP DRM (`com.pairip.*`).

### 3.7 Certificate Pinning (transport)
```bash
grep -rniE "CertificatePinner|sha256/|pin-set|network_security_config|TrustManager" <app>_apktool/
```
- OkHttp `CertificatePinner` with hard-coded `sha256/` pins (e.g. Pazarama `Pi1`).
- `res/xml/network_security_config.xml` — `<pin-set>`, cleartext policy, user-CA trust.
- On target SDK 24+ with no NSC, only **system CAs** are trusted by default.

### 3.8 Native libs & RASP
```bash
ls <app>_apktool/lib/*/                     # inspect .so files
```
- `libsigner.so` = Adjust attribution (NOT security). Watch for commercial RASP
  (Promon, GuardSquare, Appdome, Verimatrix, Arxan, freeRASP).

Record the per-protection verdict in a memory/notes table before moving to dynamic testing.

---

## 4. Dynamic Environment Setup

### 4.1 Install the app (all splits together)
```bash
adb install-multiple <app>/base.apk <app>/split_config.*.apk
# single APK:
adb install <app>/app.apk
```

### 4.2 Start frida-server (as root, Magisk)
```bash
adb push frida-server /data/local/tmp/frida-server
adb shell 'su -c "chmod 755 /data/local/tmp/frida-server"'
adb shell 'su -c "/data/local/tmp/frida-server -D"' &
frida-ps -U | head             # verify host<->device bridge
```

### 4.3 Install the proxy CA as a SYSTEM cert (defeats system-CA-only trust)
Android 7+ ignores user CAs for app traffic. On a rooted emulator, bind-mount the
HTTP Toolkit CA into the system trust store (works even when `/system` is read-only):

```bash
# 1. Compute the subject-hash filename the CA must have:
HASH=$(openssl x509 -inform PEM -subject_hash_old -in ~/.config/httptoolkit/ca.pem | head -1)

# 2. Copy existing system CAs + our CA to a writable dir, then bind-mount over cacerts:
adb shell 'su -c "mkdir -p /data/local/tmp/cacerts-copy && \
  cp /system/etc/security/cacerts/* /data/local/tmp/cacerts-copy/"'
adb push ~/.config/httptoolkit/ca.pem /data/local/tmp/${HASH}.0
adb shell "su -c 'cp /data/local/tmp/${HASH}.0 /data/local/tmp/cacerts-copy/ && \
  chown root:root /data/local/tmp/cacerts-copy/* && chmod 644 /data/local/tmp/cacerts-copy/* && \
  chcon u:object_r:system_security_cacerts_file:s0 /data/local/tmp/cacerts-copy/* && \
  mount -o bind /data/local/tmp/cacerts-copy /system/etc/security/cacerts'"
```

### 4.4 Point the device at the MITM proxy
```bash
adb shell settings put global http_proxy 10.0.2.2:8080     # host reachable from emulator
# revert later: adb shell settings put global http_proxy :0
```

---

## 5. Bypassing Runtime Protections (Frida)

### 5.1 Frida 17 gotcha (IMPORTANT)
Raw `session.create_script()` in Frida 17 has **no `Java` bridge** (`Java is not defined`).
Use the **Frida CLI**, which bundles the bridge, and keep it alive headless:

```bash
tail -f /dev/null | frida -U -f <package.name> -l bypass.js > /tmp/<app>_frida.log 2>&1 &
```
(`nohup &` alone does not persist under `run_command`; the `tail -f /dev/null` pipe keeps stdin open.)

### 5.2 Typical bypass hook set (`bypass.js`)
Combine all needed bypasses into one script loaded at spawn:

- **SSL pinning**
  - `okhttp3.CertificatePinner.check(...)` → no-op (all overloads incl. `check$okhttp`)
  - `com.android.org.conscrypt.TrustManagerImpl.checkServerTrusted/verifyChain` → return chain
  - `SSLContext.init()` → inject permissive `X509TrustManager`
  - `okhttp3.internal.tls.OkHostnameVerifier.verify()` → `true`
- **Root cloak**
  - `java.io.File.exists()` → `false` for paths ending `/su` or containing `superuser|magisk|busybox`
  - `android.os.Build.TAGS` → `"release-keys"`
  - `java.lang.Runtime.exec()` → block `su` / `which` probes
- **Install-source / anti-sideload**
  - `PackageManager.getInstallerPackageName()` / obfuscated wrappers → `"com.android.vending"`
- **Emulator (React Native)**: hook `RNDeviceModule.isEmulatorSync()` → `false`; spoof `Build.*`.
- **Root state setter** (when result is cached): hook the setter (e.g. `uh/f.s(Boolean)` → `false`).

Reference scripts in this workspace: `pazarama_frida/bypass.js`, `sodexo_frida/00_full_bypass.js`,
`otowatt_frida/trust_all.js`, `vodafone_frida/00_ssl_pinning_bypass.js`.

Confirm success: advisory dialogs are gone and traffic starts decrypting in the proxy log.

---

## 6. TLS Traffic Interception

A self-contained Python TLS proxy signs per-host leaf certs on the fly using the
HTTP Toolkit CA — no external mitmproxy install required.

```bash
python3 <app>_frida/mitm_capture.py       # listens 0.0.0.0:8080, logs /tmp/<app>_traffic.log
```

Template: `5sarj_frida/mitm_capture.py` (CA at `~/.config/httptoolkit/ca.{pem,key}`,
generates leaf certs per SNI host, logs full request/response, flags sensitive keywords,
logs upstream failures as `UPSTREAM-FAIL`).

**What to capture / document**
- Backend hosts and their roles (BFF gateway, identity/OAuth issuer, CDN/config, analytics).
- Auth model: bearer/JWT (issuer, scope, role), guest `client_credentials` tokens, OTP flow.
- Client identity headers (e.g. `X-DeviceId`, `X-AppVersion`, `X-Platform`), signing hashes.
- Endpoint inventory: bootstrap/config, public reference, authenticated user/resource calls.

> **Troubleshooting:** if some calls skip the proxy (skeleton loaders / generic error), the
> content client may use `Proxy.NO_PROXY`, gRPC/Cronet, or require HTTP/2. Options: hook
> `OkHttpClient.Builder.proxy`, or use transparent iptables redirect.

---

## 7. API Abuse Testing (Non-Destructive)

Using captured tokens/headers, probe the API **safely** with Python scripts
(`api_probe.py`, `idor_test.py`, `api_authtest.py` in the `*_frida/` dirs):

- **AuthZ enforcement:** call user/resource endpoints with (a) no token, (b) empty token,
  (c) garbage token — expect `401`. A `200` with data ⇒ broken auth.
- **IDOR:** with a valid token, request neighbouring object IDs (`/user-card/{id}`,
  `/profiles/{id}`) — data for another user's ID ⇒ IDOR.
- **OTP / login flow (report as design risk, do NOT weaponize):** note unauthenticated
  OTP dispatch (SMS-flood / cost abuse), short numeric OTP length (brute-force space),
  registered-number enumeration via differing responses.
- **Metadata exposure:** WSDL/`?singleWsdl`, Swagger, verbose errors.
- **Infra:** WAF (Cloudflare `__cf_bm`, F5 BIG-IP `TS*`), security headers (HSTS, nosniff).

**Rules:** read-only only. No OTP bombing, no payments, no password/profile mutation,
no deletions. Backends are live production systems.

---

## 8. Report Generation

Reports are generated as PDF via WeasyPrint from a self-contained Python + inline-HTML
template. Use an existing generator as the template:

```bash
python3 generate_<app>_report.py          # → <app>_security_report.pdf
```

**Standard section layout** (see `generate_5sarj_report.py`, `generate_pazarama_report.py`):
1. Executive Summary (key findings with severity chips)
2. Application Information (package, version, SDKs, hosts, tech, tools)
3. Runtime Protection Analysis (the 6 categories + pinning table, PRESENT/ADVISORY/ABSENT)
4. Transport Security & SSL Pinning (implementation + bypass)
5. API Architecture & Authentication Model (hosts, tokens, headers, endpoints)
6. Client-Side Protection Bypass (Frida hook set)
7. Risk Assessment (finding / severity / impact table)

Severity chips: `severity-critical / -high / -medium / -low / -good`.
Keep tone factual and self-contained; do not reference other engagements.

---

## 9. Cleanup

```bash
adb shell settings put global http_proxy :0                       # remove proxy
adb shell 'su -c "umount /system/etc/security/cacerts"'           # remove CA bind-mount
adb shell 'su -c "pkill frida-server"'                            # stop agent
# optionally: adb uninstall <package.name>
```

---

## Appendix: Per-App Quick Reference

| App | Package | Framework | Notable protections |
|-----|---------|-----------|---------------------|
| 5Şarj | `com.borencoevcharge` | Native Kotlin | Obfuscation only; root = Crashlytics telemetry; no pinning |
| Pazarama | `tr.com.topkapidanismanlik.pazarama.app` | Native Kotlin | **Cert pinning (real)**; advisory root + anti-sideload |
| OTOWATT | `com.ipitex.otowatt` | Native Java | None; hardcoded AES key; BODY-level logging |
| Sodexo | `com.sodexo.flexogift` | React Native | RootBeer + JailMonkey + Frida + emulator + pinning |
| Vodafone | `com.vodafone.selfservis` | Native | Weak root (`Runtime.exec su`); no pinning |
| DoctorIn | `com.pusula.doctorin` | Flutter | PAIRIP DRM; no pinning/root in Dart |
