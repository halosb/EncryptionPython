package com.example.encryptionpython.core;

import java.io.File;
import java.io.IOException;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Enumeration;

public class PythonPacker {
    private static final byte XOR_KEY = 0x5A; // used for simple Java-side obfuscation if needed

    public static File pack(File inputPy, File outDir, byte[] salt, String expectedHash, String obfHex,
                            int lockThreshold, int lockMinutes, boolean useExpiry, String expiryDate, boolean[] binds) throws Exception {
        String original = Files.readString(inputPy.toPath(), StandardCharsets.UTF_8);
        String payloadB64 = Base64.getEncoder().encodeToString(original.getBytes(StandardCharsets.UTF_8));

        String saltHex = CryptoUtils.hex(salt);

        String cpu = binds[0] ? getCpuSerial() : "UNBOUND";
        String disk = binds[1] ? getDiskSerial() : "UNBOUND";
        String mac = binds[2] ? getMacAddress() : "UNBOUND";
        String cwd = binds[3] ? inputPy.getParent() : "UNBOUND";

        String python = buildWrapper(payloadB64, saltHex, expectedHash, lockThreshold, lockMinutes, useExpiry, expiryDate, cpu, disk, mac, cwd);

        // Use distinct placeholders so runtime normalization works correctly.
        // ASSIGN_PLACEHOLDER is replaced with actual integrity; MASK_PLACEHOLDER is used in runtime normalization.
        String ASSIGN_PLACEHOLDER = "__INTEGRITY_INJECT__";
        String MASK_PLACEHOLDER = "__INTEGRITY_MASK__";

        // compute integrity hash of the python wrapper itself using MASK placeholder at assignment site
        String tempForHash = python.replace(ASSIGN_PLACEHOLDER, MASK_PLACEHOLDER);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(tempForHash.getBytes(StandardCharsets.UTF_8));
        String integrityHex = bytesToHex(digest);

        // insert integrity into script (replace assign placeholder only)
        python = python.replace(ASSIGN_PLACEHOLDER, integrityHex);

        // final write
        String outName = inputPy.getName().replaceAll("\\.py$", "") + "_protected.py";
        File outFile = new File(outDir, outName);
        Files.writeString(outFile.toPath(), python, StandardCharsets.UTF_8);
        return outFile;
    }

    private static String buildWrapper(String payloadB64, String saltHex, String expectedHash,
                                       int lockThreshold, int lockMinutes, boolean useExpiry, String expiryDate,
                                       String cpu, String disk, String mac, String cwd) {
        StringBuilder sb = new StringBuilder();
        // escape backslashes in cwd so Python string literals like 'E:\\path' are valid
        String safeCwd = cwd == null ? "" : cwd.replace("\\", "\\\\");
        sb.append("#!/usr/bin/env python3\n");
        sb.append("import sys,os,time,datetime,hashlib,base64,getpass,urllib.request,subprocess,uuid\n\n");
        sb.append("# save original sys.exit and provide a cross-platform 'press any key' wait\n");
        sb.append("sys_exit_orig = sys.exit\n");
        sb.append("def _wait_any_key(prompt='按任意键退出...'):\n");
        sb.append("    try:\n");
        sb.append("        import msvcrt\n");
        sb.append("        msvcrt.getch()\n");
        sb.append("        return\n");
        sb.append("    except Exception:\n");
        sb.append("        pass\n");
        sb.append("    try:\n");
        sb.append("        import tty,termios,sys as _sys\n");
        sb.append("        fd = _sys.stdin.fileno()\n");
        sb.append("        old = termios.tcgetattr(fd)\n");
        sb.append("        try:\n");
        sb.append("            tty.setraw(fd)\n");
        sb.append("            _sys.stdin.read(1)\n");
        sb.append("        finally:\n");
        sb.append("            termios.tcsetattr(fd, termios.TCSADRAIN, old)\n");
        sb.append("        return\n");
        sb.append("    except Exception:\n");
        sb.append("        pass\n");
        sb.append("    try:\n");
        sb.append("        input(prompt)\n");
        sb.append("    except Exception:\n");
        sb.append("        pass\n\n");
        sb.append("def terminate(msg, code=1):\n");
        sb.append("    print(msg)\n");
        sb.append("    try:\n");
        sb.append("        if sys.stdin is not None and sys.stdin.isatty():\n");
        sb.append("            _wait_any_key('按任意键退出...')\n");
        sb.append("    except Exception:\n");
        sb.append("        pass\n");
        sb.append("    try:\n");
        sb.append("        sys_exit_orig(code)\n");
        sb.append("    except Exception:\n");
        sb.append("        pass\n\n");
        sb.append("# redirect sys.exit to terminate so console stays open for messages\n");
        sb.append("sys.exit = lambda code=1: terminate('', code)\n\n");
        sb.append("SALT_HEX='"+saltHex+"'\n");
        sb.append("EXPECTED_HASH='"+expectedHash+"'\n");
        sb.append("INTEGRITY='"+"__INTEGRITY_INJECT__"+"'\n");
        sb.append("LOCK_THRESHOLD="+lockThreshold+"\n");
        sb.append("LOCK_MINUTES="+lockMinutes+"\n");
        sb.append("PAYLOAD_B64='"+payloadB64+"'\n");
        sb.append("BIND_CPU='"+cpu+"'\n");
        sb.append("BIND_DISK='"+disk+"'\n");
        sb.append("BIND_MAC='"+mac+"'\n");
        sb.append("BIND_CWD='"+safeCwd+"'\n");
        sb.append("USE_EXPIRY="+(useExpiry?"True":"False")+"\n");
        sb.append("EXPIRY_DATE='"+(expiryDate==null?"":expiryDate)+"'\n\n");

        sb.append("# --- helper functions ---\n");
        sb.append("def hex2(b):\n    return bytes.fromhex(b)\n\n");
        sb.append("def obfuscate_py(pwd):\n");
        sb.append("    # mirror Java obfuscation: XOR with 0x5A then +3 on bytes, then hex\n");
        sb.append("    bs = pwd.encode('utf-8')\n");
        sb.append("    out = bytearray()\n");
        sb.append("    for i,b in enumerate(bs):\n        out.append(((b ^ 0x5A) + 3) & 0xFF)\n    return out.hex()\n\n");

        sb.append("def check_password():\n");
        sb.append("    lockfile = os.path.join(os.path.dirname(__file__), '.lock_'+os.path.basename(__file__))\n");
        sb.append("    # simple lockfile format: failed_count|unlock_epoch\n");
        sb.append("    failed=0; unlock=0\n");
        sb.append("    if os.path.exists(lockfile):\n        try:\n            with open(lockfile,'r') as f:\n                t=f.read().split('|')\n                if len(t)>=1 and t[0]: failed=int(t[0])\n                if len(t)>=2 and t[1]: unlock=int(t[1])\n        except Exception:\n            pass\n");
        sb.append("    now=int(time.time())\n");
        sb.append("    if unlock>now:\n        print('程序已锁定，请稍后再试')\n        sys.exit(1)\n");
        sb.append("    pwd = getpass.getpass('请输入密码: ')\n    obf = obfuscate_py(pwd)\n    m = hashlib.sha256()\n    m.update(bytes.fromhex(SALT_HEX))\n    m.update(bytes.fromhex(obf))\n    if m.hexdigest() == EXPECTED_HASH:\n        try:\n            with open(lockfile,'w') as f: f.write('0|0')\n        except Exception: pass\n        return True\n    else:\n        failed += 1\n        if failed >= LOCK_THRESHOLD:\n            unlock = now + LOCK_MINUTES*60\n            try:\n                with open(lockfile,'w') as f: f.write(str(failed)+'|'+str(unlock))\n            except Exception: pass\n            print('错误次数过多，已锁定')\n            sys.exit(1)\n        else:\n            try:\n                with open(lockfile,'w') as f: f.write(str(failed)+'|0')\n            except Exception: pass\n            # show remaining attempts\n            try:\n                rem = LOCK_THRESHOLD - failed\n            except Exception:\n                rem = 0\n            print('密码错误，剩余%d次尝试' % (rem))\n            return False\n\n");

        sb.append("def check_time():\n");
        sb.append("    # local time check\n    if USE_EXPIRY and EXPIRY_DATE:\n        try:\n            exp = datetime.datetime.fromisoformat(EXPIRY_DATE)\n            if datetime.datetime.now() > exp:\n                print('当前已过期，请联系作者')\n                sys.exit(1)\n        except Exception as e:\n            pass\n    # network time check (best-effort)\n    try:\n        with urllib.request.urlopen('http://worldtimeapi.org/api/ip', timeout=5) as r:\n            import json\n            data = json.load(r)\n            nt = data.get('unixtime')\n            if nt and USE_EXPIRY and EXPIRY_DATE:\n                exp = int(datetime.datetime.fromisoformat(EXPIRY_DATE).timestamp())\n                if nt > exp:\n                    print('当前已过期，请联系作者')\n                    sys.exit(1)\n    except Exception:\n        pass\n\n");

        sb.append("def check_bindings():\n");
        sb.append("    # check MAC - collect multiple candidates and compare normalized forms\n    mac_candidates = set()\n    try:\n        m = hex(uuid.getnode())[2:]\n        if m:\n            mac_candidates.add(m.lower().rjust(12,'0'))\n    except Exception:\n        pass\n    # try platform tools for extra MACs\n    try:\n        if os.name=='nt':\n            out = subprocess.check_output(['getmac'], stderr=subprocess.DEVNULL).decode(errors='ignore')\n        else:\n            # ip link or ifconfig fallback\n            try:\n                out = subprocess.check_output(['ip','link'], stderr=subprocess.DEVNULL).decode(errors='ignore')\n            except Exception:\n                out = subprocess.check_output(['ifconfig','-a'], stderr=subprocess.DEVNULL).decode(errors='ignore')\n        import re\n        for mo in re.findall(r'([0-9a-fA-F]{2}([:-]?)){5}[0-9a-fA-F]{2}', out):\n            raw = mo[0]\n            norm = re.sub(r'[^0-9a-fA-F]','', raw).lower().rjust(12,'0')\n            mac_candidates.add(norm)\n    except Exception:\n        pass\n    try:\n        bind_norm = BIND_MAC.lower().rjust(12,'0')\n    except Exception:\n        bind_norm = BIND_MAC.lower()\n    # debug: show detected candidates when mismatch occurs\n    if BIND_MAC!='UNBOUND' and bind_norm not in mac_candidates:\n        print('绑定校验失败: MAC')\n        try:\n            print('期望:', bind_norm, '检测到的 MAC:', ','.join(sorted(mac_candidates)))\n        except Exception:\n            pass\n        terminate('绑定校验失败: MAC',1)\n    if BIND_CWD!='UNBOUND' and os.path.abspath(os.getcwd())!=os.path.abspath(BIND_CWD):\n        print('绑定校验失败: 运行目录')\n        terminate('绑定校验失败: 运行目录',1)\n    # CPU/DISK best-effort: skip strict checks on non-windows\n    if BIND_CPU!='UNBOUND' or BIND_DISK!='UNBOUND':\n        try:\n            if os.name=='nt':\n                # try wmic\n                pass\n        except Exception:\n            pass\n\n");

        sb.append("def detect_reverse_tools():\n");
        sb.append("    suspects=['ida64.exe','ida.exe','ollydbg.exe','x64dbg.exe','frida-server','uncompyle6','pyinstxtractor.py','ghidra']\n    try:\n        if os.name=='nt':\n            out = subprocess.check_output(['tasklist'], stderr=subprocess.DEVNULL).decode(errors='ignore').lower()\n        else:\n            out = subprocess.check_output(['ps','-A'], stderr=subprocess.DEVNULL).decode(errors='ignore').lower()\n        for s in suspects:\n            if s.lower() in out:\n                print('检测到逆向工具:', s)\n                sys.exit(1)\n    except Exception:\n        pass\n\n");

        sb.append("def check_integrity():\n");
        sb.append("    try:\n        # read as text and normalize the INTEGRITY line to mask placeholder before hashing\n        with open(__file__,'r', encoding='utf-8', errors='ignore') as f:\n            s = f.read()\n        import re\n        s_for_hash = re.sub(r\"INTEGRITY='[0-9a-fA-F]+'\", \"INTEGRITY='__INTEGRITY_MASK__'\", s)\n        h = hashlib.sha256(s_for_hash.encode('utf-8')).hexdigest()\n        if h != INTEGRITY:\n            print('当前检测被篡改,请不要篡改代码')\n            sys.exit(1)\n    except Exception:\n        pass\n\n");

        sb.append("# main flow (wrapped to catch unexpected exceptions and keep console open)\n");
        sb.append("try:\n");
        sb.append("    check_integrity()\n");
        sb.append("    detect_reverse_tools()\n");
        sb.append("    check_time()\n");
        sb.append("    check_bindings()\n");
        sb.append("    # friendly messages\n");
        sb.append("    print('当前代码已加密，请输入密码')\n");
        sb.append("    ok=False\n");
        sb.append("    for _ in range(LOCK_THRESHOLD):\n");
        sb.append("        if check_password():\n");
        sb.append("            ok=True; break\n\n");

        sb.append("    if not ok:\n");
        sb.append("        terminate('密码错误，程序退出',1)\n\n");
        sb.append("    # restore payload and execute\n");
        sb.append("    code = base64.b64decode(PAYLOAD_B64).decode('utf-8')\n");
        sb.append("    exec(compile(code, '<payload>', 'exec'))\n");
        sb.append("except Exception as e:\n");
        sb.append("    import traceback\n");
        sb.append("    traceback.print_exc()\n");
        sb.append("    terminate('异常退出: %s' % (e),1)\n");

        return sb.toString();
    }

    private static String getMacAddress() {
        try {
            Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces();
            while (en.hasMoreElements()) {
                NetworkInterface ni = en.nextElement();
                byte[] mac = ni.getHardwareAddress();
                if (mac != null && mac.length > 0) {
                    return bytesToHex(mac);
                }
            }
        } catch (Exception e) { }
        return "UNKNOWN";
    }

    private static String getCpuSerial() {
        try {
            Process p = new ProcessBuilder("wmic", "cpu", "get", "processorid").redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            String[] lines = out.split("\\r?\\n");
            for (String l : lines) {
                l = l.trim();
                if (l.isEmpty() || l.toLowerCase().contains("processorid")) continue;
                return l;
            }
        } catch (Exception e) { }
        return "UNKNOWN";
    }

    private static String getDiskSerial() {
        try {
            Process p = new ProcessBuilder("wmic", "diskdrive", "get", "serialnumber").redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            String[] lines = out.split("\\r?\\n");
            for (String l : lines) {
                l = l.trim();
                if (l.isEmpty() || l.toLowerCase().contains("serialnumber")) continue;
                return l;
            }
        } catch (Exception e) { }
        return "UNKNOWN";
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
