import os

REPO_DIR = "hard_complex_repo"
BASE_PKG = "com.obfuscated.app"
BASE_PATH = os.path.join(REPO_DIR, "com", "obfuscated", "app")

# -----------------------------------------------------------------------------
# LAYER 0: LEAF UTILITIES (Evidence: APIs, Strings)
# -----------------------------------------------------------------------------
file_LogWrapper = """package com.obfuscated.app.utils;
import android.util.Log;
public class LogWrapper {
    public static void m1(String v1, String v2) {
        if (v1 != null && v2 != null) Log.d(v1, v2);
    }
    public static void m2(String v1, Exception v2) {
        Log.e(v1, "Error", v2);
    }
}"""

file_StringUtils = """package com.obfuscated.app.utils;
import java.util.Locale;
public class StringUtils {
    public static boolean m3(String v1) {
        return v1 == null || v1.length() == 0;
    }
    public static String m4(String v1) {
        if (m3(v1)) return "";
        return v1.toUpperCase(Locale.US);
    }
}"""

file_ByteUtils = """package com.obfuscated.app.utils;
public class ByteUtils {
    public static String m5(byte[] v1) {
        StringBuilder sb = new StringBuilder();
        for (byte b : v1) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}"""

file_SysConfig = """package com.obfuscated.app.config;
public class SysConfig {
    public static final String F1 = "https://api.hidden-server.com/v2";
    public static final String F2 = "AES/CBC/PKCS5Padding";
    public static final int F3 = 5000;
}"""

file_NativeWrapper = """package com.obfuscated.app.jni;
public class NativeWrapper {
    static { System.loadLibrary("core_ops"); }
    public native String m6();
    public native int m7(byte[] v1);
}"""

# -----------------------------------------------------------------------------
# LAYER 1: CORE INFRASTRUCTURE (Evidence: Uses Layer 0 + Android APIs)
# -----------------------------------------------------------------------------
file_LocalStorage = """package com.obfuscated.app.io;
import android.content.Context;
import android.content.SharedPreferences;
import com.obfuscated.app.utils.StringUtils;

public class LocalStorage {
    private SharedPreferences sp;

    public LocalStorage(Context c) {
        this.sp = c.getSharedPreferences("app_prefs", 0);
    }

    // Hint: Saves String
    public void m8(String k, String v) {
        if (StringUtils.m3(k)) return;
        this.sp.edit().putString(k, v).apply();
    }

    // Hint: Gets String
    public String m9(String k) {
        return this.sp.getString(k, null);
    }

    // Hint: Clear
    public void m10() {
        this.sp.edit().clear().commit();
    }
}"""

file_CryptoEngine = """package com.obfuscated.app.security;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import android.util.Base64;
import com.obfuscated.app.config.SysConfig;
import com.obfuscated.app.utils.LogWrapper;

public class CryptoEngine {

    // Hint: Encrypt AES
    public String m11(String v1, String key) {
        try {
            SecretKeySpec sk = new SecretKeySpec(key.getBytes(), "AES");
            Cipher c = Cipher.getInstance(SysConfig.F2);
            c.init(1, sk);
            byte[] enc = c.doFinal(v1.getBytes());
            return Base64.encodeToString(enc, 0);
        } catch (Exception e) {
            LogWrapper.m2("Crypto", e);
            return null;
        }
    }

    // Hint: Decrypt
    public String m12(String v1, String key) {
        try {
            SecretKeySpec sk = new SecretKeySpec(key.getBytes(), "AES");
            Cipher c = Cipher.getInstance(SysConfig.F2);
            c.init(2, sk);
            byte[] dec = c.doFinal(Base64.decode(v1, 0));
            return new String(dec);
        } catch (Exception e) { return null; }
    }
}"""

file_NetClient = """package com.obfuscated.app.net;
import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import com.obfuscated.app.config.SysConfig;
import com.obfuscated.app.utils.LogWrapper;

public class NetClient {

    // Hint: POST Request
    public void m13(String path, String data) {
        try {
            URL u = new URL(SysConfig.F1 + path);
            HttpURLConnection c = (HttpURLConnection) u.openConnection();
            c.setRequestMethod("POST");
            c.setDoOutput(true);
            c.setConnectTimeout(SysConfig.F3);

            OutputStream os = c.getOutputStream();
            os.write(data.getBytes());
            os.close();

            int code = c.getResponseCode();
            LogWrapper.m1("Net", "Response: " + code);
        } catch (Exception e) {
            LogWrapper.m2("Net", e);
        }
    }
}"""

file_FileHandler = """package com.obfuscated.app.io;
import java.io.File;
import java.io.FileOutputStream;

public class FileHandler {
    // Hint: Write bytes to file
    public boolean m14(String path, byte[] d) {
        try {
            FileOutputStream fos = new FileOutputStream(new File(path));
            fos.write(d);
            fos.close();
            return true;
        } catch(Exception e) { return false; }
    }
}"""

# -----------------------------------------------------------------------------
# LAYER 2: SERVICES (Evidence: Uses Layer 1)
# -----------------------------------------------------------------------------
file_AuthService = """package com.obfuscated.app.services;
import com.obfuscated.app.net.NetClient;
import com.obfuscated.app.security.CryptoEngine;
import com.obfuscated.app.io.LocalStorage;

public class AuthService {
    private NetClient nc;
    private CryptoEngine ce;
    private LocalStorage ls;

    public AuthService(NetClient n, CryptoEngine c, LocalStorage l) {
        this.nc = n; this.ce = c; this.ls = l;
    }

    // Hint: Login Flow
    public void m15(String u, String p) {
        String encP = this.ce.m11(p, "StaticKey1234");
        String json = "{\\"user\\":\\"" + u + "\\", \\"pass\\":\\"" + encP + "\\"}";
        this.nc.m13("/auth/login", json);
        this.ls.m8("last_user", u);
    }

    // Hint: Logout
    public void m16() {
        this.ls.m10();
    }
}"""

file_SyncService = """package com.obfuscated.app.services;
import com.obfuscated.app.net.NetClient;
import com.obfuscated.app.io.LocalStorage;

public class SyncService {
    // Hint: Sync Data
    public void m17(NetClient nc, LocalStorage ls) {
        String token = ls.m9("auth_token");
        if (token != null) {
            nc.m13("/data/sync", "token=" + token);
        }
    }
}"""

file_AnalyticsMgr = """package com.obfuscated.app.services;
import com.obfuscated.app.net.NetClient;
import android.os.Build;

public class AnalyticsMgr {
    // Hint: Send Device Info
    public static void m18(NetClient nc) {
        String info = Build.MANUFACTURER + " " + Build.MODEL;
        nc.m13("/stats/device", info);
    }
}"""

file_CrashHandler = """package com.obfuscated.app.services;
import com.obfuscated.app.utils.LogWrapper;
import java.lang.Thread.UncaughtExceptionHandler;

public class CrashHandler implements UncaughtExceptionHandler {
    public void uncaughtException(Thread t, Throwable e) {
        LogWrapper.m2("Crash", (Exception)e);
        // Maybe kill process here
        System.exit(1);
    }
}"""

file_ImageLoader = """package com.obfuscated.app.services;
import com.obfuscated.app.net.NetClient;
import com.obfuscated.app.io.FileHandler;

public class ImageLoader {
    // Hint: Download and Save
    public void m19(String url, String path) {
        // Mock download logic
        byte[] dummy = new byte[100];
        new FileHandler().m14(path, dummy);
    }
}"""

# -----------------------------------------------------------------------------
# LAYER 3: FEATURE MANAGERS (Evidence: Uses Layer 2)
# -----------------------------------------------------------------------------
file_ChatSession = """package com.obfuscated.app.features;
import com.obfuscated.app.io.LocalStorage;
import com.obfuscated.app.net.NetClient;

public class ChatSession {
    // Hint: Send Message
    public void m20(String msg) {
        new NetClient().m13("/chat/send", msg);
    }

    // Hint: Get History (Mock)
    public String m21() {
        return "Last message";
    }
}"""

file_WalletMgr = """package com.obfuscated.app.features;
import com.obfuscated.app.security.CryptoEngine;
import com.obfuscated.app.io.LocalStorage;

public class WalletMgr {
    private CryptoEngine ce = new CryptoEngine();

    // Hint: Save Credit Card
    public void m22(String cc, LocalStorage ls) {
        String enc = ce.m11(cc, "WalletKey999");
        ls.m8("wallet_cc", enc);
    }

    // Hint: Get Balance
    public double m23() {
        return 0.00;
    }
}"""

file_ProfileMgr = """package com.obfuscated.app.features;
import com.obfuscated.app.io.LocalStorage;
import com.obfuscated.app.services.ImageLoader;

public class ProfileMgr {
    // Hint: Update Avatar
    public void m24(String path) {
        new ImageLoader().m19("http://avatar.url", path);
    }

    // Hint: Set Display Name
    public void m25(String name, LocalStorage ls) {
        ls.m8("disp_name", name);
    }
}"""

file_SettingsMgr = """package com.obfuscated.app.features;
import com.obfuscated.app.io.LocalStorage;

public class SettingsMgr {
    // Hint: Toggle Notifications
    public void m26(boolean on, LocalStorage ls) {
        ls.m8("notif_enabled", String.valueOf(on));
    }
}"""

file_LocationTracker = """package com.obfuscated.app.features;
import com.obfuscated.app.net.NetClient;

public class LocationTracker {
    // Hint: Send GPS
    public void m27(double lat, double lon) {
        new NetClient().m13("/gps/track", lat + "," + lon);
    }
}"""

# -----------------------------------------------------------------------------
# LAYER 4: UI / APP (Evidence: Orchestration)
# -----------------------------------------------------------------------------
file_AppGlobal = """package com.obfuscated.app;
import android.app.Application;
import com.obfuscated.app.services.CrashHandler;
import com.obfuscated.app.config.SysConfig;

public class AppGlobal extends Application {
    public void onCreate() {
        super.onCreate();
        // Init crash handler
        Thread.setDefaultUncaughtExceptionHandler(new CrashHandler());
    }
}"""

file_MainEntry = """package com.obfuscated.app.ui;
import android.app.Activity;
import android.os.Bundle;
import com.obfuscated.app.services.AuthService;
import com.obfuscated.app.features.ChatSession;
import com.obfuscated.app.io.LocalStorage;

public class MainEntry extends Activity {
    private AuthService as;
    private ChatSession cs;

    // Hint: OnCreate
    public void m28(Bundle b) {
        this.as = new AuthService(null, null, new LocalStorage(this));
        this.cs = new ChatSession();

        if (b == null) {
            this.as.m15("default_user", "123456"); // Auto login
        }
    }

    // Hint: Click Send
    public void m29(String txt) {
        this.cs.m20(txt);
    }
}"""

file_LoginScreen = """package com.obfuscated.app.ui;
import com.obfuscated.app.services.AuthService;

public class LoginScreen {
    // Hint: Perform Login
    public void m30(AuthService as, String u, String p) {
        as.m15(u, p);
    }
}"""

file_WalletScreen = """package com.obfuscated.app.ui;
import com.obfuscated.app.features.WalletMgr;
import com.obfuscated.app.io.LocalStorage;

public class WalletScreen {
    // Hint: Add Card
    public void m31(String num) {
        new WalletMgr().m22(num, new LocalStorage(null));
    }
}"""

# -----------------------------------------------------------------------------
# DUMMY INTERFACES / ABSTRACTS (To add noise)
# -----------------------------------------------------------------------------
file_BaseCallback = """package com.obfuscated.app.base;
public interface BaseCallback {
    void onDone(Object o);
    void onFail(int code);
}"""

file_AbstractModel = """package com.obfuscated.app.base;
public abstract class AbstractModel {
    public abstract String getId();
    public String getType() { return "Generic"; }
}"""

file_ViewBase = """package com.obfuscated.app.base;
public class ViewBase {
    public void render() {}
    public void refresh() {}
}"""

# -----------------------------------------------------------------------------
# GENERATOR
# -----------------------------------------------------------------------------
files_map = {
    "utils/LogWrapper.java": file_LogWrapper,
    "utils/StringUtils.java": file_StringUtils,
    "utils/ByteUtils.java": file_ByteUtils,
    "config/SysConfig.java": file_SysConfig,
    "jni/NativeWrapper.java": file_NativeWrapper,
    "io/LocalStorage.java": file_LocalStorage,
    "io/FileHandler.java": file_FileHandler,
    "security/CryptoEngine.java": file_CryptoEngine,
    "net/NetClient.java": file_NetClient,
    "services/AuthService.java": file_AuthService,
    "services/SyncService.java": file_SyncService,
    "services/AnalyticsMgr.java": file_AnalyticsMgr,
    "services/CrashHandler.java": file_CrashHandler,
    "services/ImageLoader.java": file_ImageLoader,
    "features/ChatSession.java": file_ChatSession,
    "features/WalletMgr.java": file_WalletMgr,
    "features/ProfileMgr.java": file_ProfileMgr,
    "features/SettingsMgr.java": file_SettingsMgr,
    "features/LocationTracker.java": file_LocationTracker,
    "ui/MainEntry.java": file_MainEntry,
    "ui/LoginScreen.java": file_LoginScreen,
    "ui/WalletScreen.java": file_WalletScreen,
    "AppGlobal.java": file_AppGlobal,
    "base/BaseCallback.java": file_BaseCallback,
    "base/AbstractModel.java": file_AbstractModel,
    "base/ViewBase.java": file_ViewBase
}


def generate():
    print(f"[*] Generating HARD COMPLEX REPO at: {REPO_DIR}")

    for rel_path, content in files_map.items():
        # Determine full path
        if "/" in rel_path:
            # It's inside a package subfolder
            full_path = os.path.join(BASE_PATH, rel_path.replace("/", os.sep))
        else:
            # It's in the base package root
            full_path = os.path.join(BASE_PATH, rel_path)

        # Ensure dir exists
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        # Write
        with open(full_path, "w") as f:
            f.write(content)
        print(f"    [+] {rel_path}")

    print(f"[*] Done. {len(files_map)} files created.")


if __name__ == "__main__":
    generate()
	
import os

# Define the structure of the fake decompiled repository
REPO_DIR = "decompiled_repo"
PACKAGE_PATH = os.path.join(REPO_DIR, "com", "example", "app")

files = {
    # 1. Main Entry Point (Android Activity)
    "MainActivity.java": """package com.example.app;

import android.os.Bundle;
import android.app.Activity;
import com.example.app.utils.NetworkUtils;
import com.example.app.models.UserSession;

public class MainActivity extends Activity {
    public UserSession session;
    private String TAG = "MainActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(2130968601); // R.layout.activity_main

        this.session = new UserSession();
        this.sub_1a2b();
    }

    private void sub_1a2b() {
        String var1 = "https://api.example.com/config";
        NetworkUtils.sub_4f5g(var1, new NetworkUtils.Callback() {
            public void onSuccess(String var2) {
                MainActivity.this.sub_8h9i(var2);
            }
        });
    }

    /* * WaveFunc should identify this as 'processConfig' or 'handleResponse'
     * based on the usage of Strings and context.
     */
    private void sub_8h9i(String var1) {
        if (var1 != null && var1.length() > 0) {
            if (var1.contains("maintenance_mode")) {
                this.sub_9j0k("Maintenance", "Server is down");
            } else {
                this.session.sub_s1s2(var1);
            }
        }
    }

    private void sub_9j0k(String title, String msg) {
        // Obfuscated Dialog builder
        android.app.AlertDialog.Builder var1 = new android.app.AlertDialog.Builder(this);
        var1.setTitle(title);
        var1.setMessage(msg);
        var1.show();
    }
}
""",

    # 2. Networking Helper (Static Utility Class)
    "NetworkUtils.java": """package com.example.app.utils;

import java.net.HttpURLConnection;
import java.net.URL;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class NetworkUtils {

    public interface Callback {
        void onSuccess(String result);
    }

    /*
     * WaveFunc should rename this to 'makeGetRequest' or 'fetchUrl'
     */
    public static void sub_4f5g(final String var1, final Callback var2) {
        new Thread(new Runnable() {
            public void run() {
                try {
                    URL url = new URL(var1);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");

                    int code = conn.getResponseCode();
                    if (code == 200) {
                        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                        StringBuilder sb = new StringBuilder();
                        String line;
                        while ((line = br.readLine()) != null) {
                            sb.append(line);
                        }
                        br.close();
                        var2.onSuccess(sb.toString());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }).start();
    }

    public static String sub_x9y8(String param) {
        return "Bearer " + param;
    }
}
""",

    # 3. Data Model (Session Management)
    "UserSession.java": """package com.example.app.models;

public class UserSession {
    private String token;
    private long expiry;
    private boolean isActive;

    public UserSession() {
        this.isActive = false;
    }

    /*
     * WaveFunc should rename to 'setToken' or 'updateSession'
     */
    public void sub_s1s2(String var1) {
        this.token = var1;
        this.expiry = System.currentTimeMillis() + 3600000L;
        this.isActive = true;
    }

    public boolean sub_c3c4() {
        return this.isActive && System.currentTimeMillis() < this.expiry;
    }

    public String sub_g5g6() {
        if (sub_c3c4()) {
            return this.token;
        }
        return null;
    }
}
""",

    # 4. Crypto Helper (Complex Logic)
    "CryptoHelper.java": """package com.example.app.security;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import android.util.Base64;

public class CryptoHelper {

    private static final String ALG = "AES";

    /*
     * WaveFunc should rename to 'encryptString'
     */
    public static String sub_enc1(String var1, String key) {
        try {
            SecretKeySpec skey = new SecretKeySpec(key.getBytes(), ALG);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(1, skey);
            byte[] encrypted = cipher.doFinal(var1.getBytes());
            return Base64.encodeToString(encrypted, 0);
        } catch (Exception e) {
            return null;
        }
    }

    /*
     * WaveFunc should rename to 'sha256Hash' or 'generateHash'
     */
    public static String sub_h2h3(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes("UTF-8"));
            StringBuffer hexString = new StringBuffer();
            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if(hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
""",

    # 5. Database Manager (Local Storage)
    "DatabaseManager.java": """package com.example.app.db;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.content.ContentValues;

public class DatabaseManager extends SQLiteOpenHelper {

    public DatabaseManager(Context context) {
        super(context, "app_data.db", null, 1);
    }

    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)");
    }

    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS users");
        onCreate(db);
    }

    /*
     * WaveFunc should rename to 'addUser' or 'insertUser'
     */
    public void sub_d1d2(String name, String email) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("name", name);
        cv.put("email", email);
        db.insert("users", null, cv);
        db.close();
    }
}
"""
}


def generate_repo():
    # Create base package directories
    dirs = [
        os.path.join(PACKAGE_PATH, "utils"),
        os.path.join(PACKAGE_PATH, "models"),
        os.path.join(PACKAGE_PATH, "security"),
        os.path.join(PACKAGE_PATH, "db")
    ]

    for d in dirs:
        os.makedirs(d, exist_ok=True)

    # Write files
    # Mappings to correct subfolders
    path_map = {
        "MainActivity.java": PACKAGE_PATH,
        "NetworkUtils.java": os.path.join(PACKAGE_PATH, "utils"),
        "UserSession.java": os.path.join(PACKAGE_PATH, "models"),
        "CryptoHelper.java": os.path.join(PACKAGE_PATH, "security"),
        "DatabaseManager.java": os.path.join(PACKAGE_PATH, "db"),
    }

    print(f"[*] Generating Decompiled Repo at: {REPO_DIR}")
    for filename, content in files.items():
        full_path = os.path.join(path_map[filename], filename)
        with open(full_path, "w") as f:
            f.write(content)
        print(f"    [+] Created {filename}")

    print("[*] Done! Ready for WaveFunc analysis.")


if __name__ == "__main__":
    generate_repo()
	
import os

REPO_DIR = "hard_repo"
PKG_ROOT = os.path.join(REPO_DIR, "com", "secure", "chat")

files = {
    # ---------------------------------------------------------
    # 1. CryptoUtils (The Foundation - Wave 1 Target)
    # ---------------------------------------------------------
    "CryptoUtils.java": """package com.secure.chat.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;
import android.util.Base64;
import java.util.Random;

public class CryptoUtils {

    // Wave 1: Evidence is strong (AES, Cipher)
    public static String sub_c1(String data, String key) {
        try {
            SecretKeySpec sKey = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(1, sKey, new IvParameterSpec(new byte[16]));
            return Base64.encodeToString(cipher.doFinal(data.getBytes()), 0);
        } catch (Exception e) { return null; }
    }

    // Wave 1: Evidence is strong (SHA-256)
    public static String sub_c2(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for(byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return ""; }
    }

    // Wave 2: Ambiguous. Just generates random bytes.
    // Needs context to know it's for "IV Generation" or "Salt".
    public static byte[] sub_c3(int len) {
        byte[] b = new byte[len];
        new Random().nextBytes(b);
        return b;
    }
}
""",

    # ---------------------------------------------------------
    # 2. NetworkAdapter (The Transport - Wave 1/2 Target)
    # ---------------------------------------------------------
    "NetworkAdapter.java": """package com.secure.chat.net;

import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import com.secure.chat.crypto.CryptoUtils;

public class NetworkAdapter {
    private String baseUrl = "https://api.securechat.com/v1";

    // Wave 2: Calls CryptoUtils.sub_c1 (Encrypt).
    // Should be named 'postEncryptedData' or similar.
    public void sub_n1(String endpoint, String payload, String key) {
        String encrypted = CryptoUtils.sub_c1(payload, key);
        this.sub_n2(endpoint, encrypted);
    }

    // Wave 1: Strong API evidence (HttpURLConnection, POST)
    private void sub_n2(String path, String data) {
        try {
            URL url = new URL(baseUrl + path);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-Auth-Sig", CryptoUtils.sub_c2(data)); // Hash signature

            OutputStream os = conn.getOutputStream();
            os.write(data.getBytes());
            os.flush();
            os.close();
            conn.getResponseCode();
        } catch (Exception e) { e.printStackTrace(); }
    }

    // Wave 1: Simple formatting
    public String sub_n3(String token) {
        return "Bearer " + token;
    }
}
""",

    # ---------------------------------------------------------
    # 3. DatabaseHandler (Local Storage - Wave 1 Target)
    # ---------------------------------------------------------
    "DatabaseHandler.java": """package com.secure.chat.db;

import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.content.ContentValues;
import android.database.Cursor;
import java.util.ArrayList;
import java.util.List;

public class DatabaseHandler extends SQLiteOpenHelper {

    // Wave 1: SQL String evidence
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE messages (id INTEGER PRIMARY KEY, user TEXT, content TEXT, ts LONG)");
    }

    public void onUpgrade(SQLiteDatabase db, int o, int n) {}

    // Wave 1: Database Insert APIs
    public void sub_d1(String user, String msg) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues cv = new ContentValues();
        cv.put("user", user);
        cv.put("content", msg);
        cv.put("ts", System.currentTimeMillis());
        db.insert("messages", null, cv);
    }

    // Wave 1: Cursor/Query logic
    public List<String> sub_d2(String user) {
        List<String> list = new ArrayList<>();
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor c = db.rawQuery("SELECT content FROM messages WHERE user=?", new String[]{user});
        if (c.moveToFirst()) {
            do {
                list.add(c.getString(0));
            } while (c.moveToNext());
        }
        c.close();
        return list;
    }

    // Wave 2: Wrapper around delete
    public void sub_d3() {
        this.getWritableDatabase().delete("messages", null, null);
    }
}
""",

    # ---------------------------------------------------------
    # 4. FileUtils (IO - Wave 1 Target)
    # ---------------------------------------------------------
    "FileUtils.java": """package com.secure.chat.io;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;

public class FileUtils {

    // Wave 1: File Output Stream
    public static void sub_f1(String path, String data) {
        try {
            File f = new File(path);
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(data.getBytes());
            fos.close();
        } catch(Exception e) {}
    }

    // Wave 1: File Input Stream
    public static String sub_f2(String path) {
        try {
            File f = new File(path);
            FileInputStream fis = new FileInputStream(f);
            byte[] data = new byte[(int) f.length()];
            fis.read(data);
            fis.close();
            return new String(data);
        } catch(Exception e) { return null; }
    }
}
""",

    # ---------------------------------------------------------
    # 5. AuthHandler (Business Logic - Wave 2/3 Target)
    # ---------------------------------------------------------
    "AuthHandler.java": """package com.secure.chat.auth;

import com.secure.chat.net.NetworkAdapter;
import com.secure.chat.db.DatabaseHandler;
import com.secure.chat.crypto.CryptoUtils;

public class AuthHandler {
    private NetworkAdapter net;
    private DatabaseHandler db;
    private String sessionKey;

    public AuthHandler(NetworkAdapter n, DatabaseHandler d) {
        this.net = n;
        this.db = d;
    }

    // Wave 3: Uses Network(sub_n1) and Crypto(sub_c2)
    // Should be 'loginUser'
    public boolean sub_a1(String u, String p) {
        String hash = CryptoUtils.sub_c2(p); // Hash password
        String payload = "user=" + u + "&hash=" + hash;

        // This generates a random session key (Wave 2 dependency)
        this.sessionKey = new String(CryptoUtils.sub_c3(16)); 

        try {
            this.net.sub_n1("/auth/login", payload, this.sessionKey);
            return true;
        } catch (Exception e) { return false; }
    }

    // Wave 2: Wrapper. Needs context of DatabaseHandler.sub_d3 (deleteAll)
    // Should be 'logout' or 'clearSession'
    public void sub_a2() {
        this.sessionKey = null;
        this.db.sub_d3(); // Clears messages
    }
}
""",

    # ---------------------------------------------------------
    # 6. CoreManager (The Orchestrator - Wave 3/4 Target)
    # ---------------------------------------------------------
    "CoreManager.java": """package com.secure.chat;

import com.secure.chat.auth.AuthHandler;
import com.secure.chat.io.FileUtils;
import com.secure.chat.net.NetworkAdapter;
import com.secure.chat.db.DatabaseHandler;

public class CoreManager {
    private AuthHandler auth;
    private FileUtils files;
    private NetworkAdapter net;
    private DatabaseHandler db;

    public void init() {
        this.net = new NetworkAdapter();
        this.db = new DatabaseHandler(null); // Context null for mock
        this.auth = new AuthHandler(this.net, this.db);
    }

    // Wave 4: The Ultimate Hard Logic.
    // Calls Auth.sub_a1 (Login)
    // Calls FileUtils.sub_f1 (Write Config)
    public void sub_m1(String user, String pass) {
        boolean success = this.auth.sub_a1(user, pass);
        if (success) {
            String config = "last_user=" + user;
            FileUtils.sub_f1("/data/config.ini", config);
        }
    }

    // Wave 4: Message Sending logic
    // Calls Network.sub_n3 (Bearer Token)
    // Calls Network.sub_n1 (Post Encrypted)
    // Calls Database.sub_d1 (Insert Message)
    public void sub_m2(String msg) {
        String token = this.net.sub_n3("SessionToken");
        this.net.sub_n1("/messages/send", msg, "StaticKey"); 
        this.db.sub_d1("me", msg);
    }

    // Wave 3: Sync Logic
    // Calls Database.sub_d2 (Get Messages)
    // Calls FileUtils.sub_f1 (Write Backup)
    public void sub_m3() {
        java.util.List<String> logs = this.db.sub_d2("me");
        StringBuilder sb = new StringBuilder();
        for(String s : logs) sb.append(s).append("\\n");
        FileUtils.sub_f1("/sdcard/backup.txt", sb.toString());
    }
}
"""
}


def generate_hard_repo():
    print(f"[*] Generating HARD Repo at: {REPO_DIR}")

    # 1. Map files to their package folders
    path_map = {
        "CryptoUtils.java": os.path.join(PKG_ROOT, "crypto"),
        "NetworkAdapter.java": os.path.join(PKG_ROOT, "net"),
        "DatabaseHandler.java": os.path.join(PKG_ROOT, "db"),
        "FileUtils.java": os.path.join(PKG_ROOT, "io"),
        "AuthHandler.java": os.path.join(PKG_ROOT, "auth"),
        "CoreManager.java": PKG_ROOT,
    }

    # 2. Create directories
    for folder in path_map.values():
        os.makedirs(folder, exist_ok=True)

    # 3. Write files
    for filename, content in files.items():
        full_path = os.path.join(path_map[filename], filename)
        with open(full_path, "w") as f:
            f.write(content)
        print(f"    [+] Created {filename}")

    print("[*] Hard Repo Ready.")


if __name__ == "__main__":
    generate_hard_repo()
	
import os


class Config:
    # --- API Keys ---
    OPENAI_API_KEY = 'sk-ollama'

    # --- Models ---
    # Fast model for easy functions (Getters/Setters/Simple logic)
    MODEL_FAST = "ollama/qwen2.5:3b"
    # Smart model for complex logic (Cryptography/Auth/Protocols)
    MODEL_SMART = "ollama/qwen2.5-coder:14b"

    # --- Thresholds ---
    MAX_FUNCTIONS = 500  # Safety limit
    BATCH_SIZE = 10  # Parallel naming batch size

    # --- Repo Settings ---
    # Ignore these when scanning to save time
    IGNORE_DIRS = {
        "build", "dist", "out", "target", ".git",
        "android", "androidx", "kotlin", "google", "javax"
    }

    # Cache to prevent re-billing
    CACHE_FILE = "wavefunc_cache.json"
	
	
import heapq
import threading
from config import Config


class FunctionNode:
    def __init__(self, data):
        self.id = data['id']
        self.original_name = data['name']
        self.file_path = data['file']
        self.features = data['features']

        self.suggested_name = None
        self.is_renamed = False  # <--- THE FLAG YOU WANTED
        self.confidence = "NONE"

        self.callers = set()
        self.callees = set(self.features.get('callees', []))

        self.base_score = self._calc_score()
        self.dynamic_score = 0.0

    def _calc_score(self):
        score = 0.0
        # Boost if we have a semantic summary
        if self.features.get('semantic_summary'):
            score += 5.0

        score += len(self.features.get('strings', [])) * 3.0
        score += len(self.features.get('api_calls', [])) * 2.0
        return score

    def get_priority(self):
        return self.base_score + self.dynamic_score


class RippleGraph:
    def __init__(self):
        self.nodes = {}
        self.pq = []
        self.lock = threading.Lock()

    def load_functions(self, functions_list):
        for func_data in functions_list:
            self.nodes[func_data['id']] = FunctionNode(func_data)

        # Build Reverse Edges
        for node in self.nodes.values():
            for callee_id in node.callees:
                if callee_id in self.nodes:
                    self.nodes[callee_id].callers.add(node.id)

    def initialize_queue(self):
        """Push ALL nodes to queue, even low priority ones."""
        self.pq = []
        for node in self.nodes.values():
            priority = node.get_priority()
            if priority == 0: priority = 0.1
            heapq.heappush(self.pq, (-priority, node.id))

    def get_batch(self, size=5):
        batch = []
        with self.lock:
            while len(batch) < size and self.pq:
                p, nid = heapq.heappop(self.pq)
                if nid in self.nodes:
                    node = self.nodes[nid]
                    if not node.is_renamed:
                        batch.append(node)
        return batch

    def update_node(self, func_id, name, confidence, reasoning):
        with self.lock:
            if func_id not in self.nodes: return
            node = self.nodes[func_id]

            node.suggested_name = name
            node.confidence = confidence
            node.reasoning = reasoning

            # LOGIC: A node is "renamed" if it has a new name different from original
            if name != node.original_name:
                node.is_renamed = True

            # Ripple!
            if confidence in ["HIGH", "MEDIUM"]:
                for nid in node.callers.union(node.callees):
                    if nid in self.nodes and not self.nodes[nid].is_renamed:
                        self.nodes[nid].dynamic_score += 10.0
                        heapq.heappush(self.pq, (-self.nodes[nid].get_priority(), nid))
						

import json
import hashlib
import os
import re
from litellm import completion
from config import Config


class NamingAgent:
    def __init__(self):
        self.cache = self._load_cache()

    def _load_cache(self):
        if os.path.exists(Config.CACHE_FILE):
            try:
                with open(Config.CACHE_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def _save_cache(self):
        with open(Config.CACHE_FILE, 'w') as f:
            json.dump(self.cache, f, indent=2)

    def _extract_json(self, text):
        """Robustly find JSON object in messy LLM output."""
        try:
            # Attempt 1: Direct parse
            return json.loads(text)
        except:
            pass

        try:
            # Attempt 2: Find { ... } block
            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                return json.loads(match.group())
        except:
            pass

        return None

    def summarize_code(self, code_snippet):
        """Phase 1: Semantic Extraction"""
        if not code_snippet or len(code_snippet) < 10:
            return "Empty function"

        sig = hashlib.md5(f"SUM:{code_snippet}".encode()).hexdigest()
        if sig in self.cache: return self.cache[sig]

        try:
            resp = completion(
                model=Config.MODEL_SMART,
                api_base="http://localhost:11434",
                api_key="ollama",
                messages=[{
                    "role": "system",
                    "content": "Summarize the INTENT of this Java function in 3-5 words. Use active verbs (e.g., 'Validates user session', 'Encrypts payload'). Do not describe variables."
                }, {
                    "role": "user",
                    "content": code_snippet
                }]
            )
            summary = resp.choices[0].message.content.strip()
            self.cache[sig] = summary
            self._save_cache()
            return summary
        except Exception:
            return "Complex logic"

    def analyze(self, node, neighbor_context):
            """Phase 2: Naming Strategy"""
            data = {
                "original_name": node.original_name,
                "class_context": node.id.split('.')[-2],
                "logic_summary": node.features.get('semantic_summary', 'None'),
                "strings": node.features.get('strings', [])[:5],
                "apis": node.features.get('api_calls', [])[:8],
                "known_neighbors": neighbor_context
            }

            sig = hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()
            if sig in self.cache: return self.cache[sig]

            sys_prompt = """You are a Technical Documentation Writer for Android.
            Task: Rename the function and provide a FUNCTIONAL description.
        
            ### OUTPUT FORMAT:
            Return a single JSON object:
            {
              "name": "suggestedName",
              "confidence": "HIGH",
              "reasoning": "A concise technical description of WHAT the code does. Do not mention 'evidence', 'summary', or 'logic'. Just describe the action."
            }
        
            ### EXAMPLES OF REASONING:
            - Bad: "I chose this name because the summary says it encrypts."
            - Good: "Encrypts the user password using AES-256-ECB and returns a Base64 string."
            - Bad: "The function connects to the API."
            - Good: "Initiates a GET request to the config endpoint and parses the JSON response."
        
            ### NAMING RULES:
            1. Format: camelCase (verbNoun).
            2. No Redundancy: NO 'getFetch', 'getCalculate'.
            3. Boolean: Start with 'is', 'has', 'can'.
            4. **Wrappers**: If the function just calls a neighbor (e.g. calls 'sendMessage'), adopt the neighbor's verb (e.g., 'triggerSendMessage'). DO NOT use 'delegate', 'proxy', or 'wrapper'.
            """
            try:
                resp = completion(
                    model=Config.MODEL_SMART,
                    api_base="http://localhost:11434",
                    api_key="ollama",
                    messages=[
                        {"role": "system", "content": sys_prompt},
                        {"role": "user", "content": json.dumps(data)}
                    ],
                    format="json"
                )

                result = self._extract_json(resp.choices[0].message.content)

                if not result or "name" not in result:
                    result = {"name": node.original_name, "confidence": "FAIL", "reasoning": "Analysis failed"}

                # --- PYTHON POST-PROCESSING ---
                name = result.get("name", "")
                summary = str(data['logic_summary']).lower()

                # Fix: Strip "get" from non-getters
                action_verbs = ["insert", "set", "init", "create", "delete", "update", "post", "send"]
                if name.startswith("get") and any(summary.startswith(v) for v in action_verbs):
                    if len(name) > 3:
                        name = name[3].lower() + name[4:]

                result["name"] = name

                # Fallback for empty reasoning
                if "reasoning" not in result or len(result["reasoning"]) < 5:
                    result["reasoning"] = data['logic_summary']  # Use the raw summary as fallback

                self.cache[sig] = result
                self._save_cache()
                return result
            except Exception as e:
                print(f"Agent Error: {e}")
                return {"name": node.original_name, "confidence": "FAIL", "reasoning": str(e)}


    def validate_name(self, node, neighbor_context):
        """Phase 3: Validation & Refinement"""
        # We assume the node ALREADY has a suggested name from Phase 2
        current_name = node.suggested_name

        data = {
            "current_name": current_name,
            "original_obfuscated_name": node.original_name,
            "logic_summary": node.features.get('semantic_summary', 'None'),
            "neighbors": neighbor_context
        }

        # Unique signature for validation cache
        sig = hashlib.md5(f"VAL:{json.dumps(data, sort_keys=True)}".encode()).hexdigest()
        if sig in self.cache: return self.cache[sig]

        sys_prompt = """You are a Code Reviewer.
        Task: Validate if the 'current_name' accurately reflects the function's logic and its neighbors.
        
        RULES:
        1. **Keep it** if it's good.
        2. **Refine it** if context allows a more specific name.
           - Example: 'initData' -> 'initializeDatabase' (because it calls 'connectDb').
        3. **Fix Generic Names**: If name is 'process', 'handle', 'doIt', you MUST rename it.
        
        OUTPUT JSON:
        {
          "is_valid": true/false,
          "better_name": "string (only if is_valid is false, otherwise null)",
          "reason": "Why you kept or changed it"
        }
        """
        try:
            resp = completion(
                model=Config.MODEL_SMART,
                api_base="http://localhost:11434",
                api_key="ollama",
                messages=[
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": json.dumps(data)}
                ],
                format="json"
            )

            result = self._extract_json(resp.choices[0].message.content)

            # Fallback
            if not result: return {"is_valid": True, "better_name": None, "reason": "Validation Failed"}

            self.cache[sig] = result
            self._save_cache()
            return result
        except Exception:
            return {"is_valid": True, "better_name": None, "reason": "Error"}
			
import json
from repo_parser import RepoParser
from core_engine import RippleGraph
from llm_agent import NamingAgent
from config import Config


def main():
    repo_path = 'decompiled_repos/hard_complex_repo/com'
    # Init Agent
    agent = NamingAgent()

    # 1. Parse Repo
    print(">>> Phase 1: Parsing AST...")
    repo_parser = RepoParser(repo_path)
    # Note: repo_parser.scan_repo() populates repo_parser.functions
    repo_parser.scan_repo()
    functions_list = list(repo_parser.functions.values())

    # This modifies functions_list in-place with semantic summaries
    repo_parser.enrich_functions(agent)

    # 3. Init Graph
    graph = RippleGraph()
    graph.load_functions(functions_list)
    graph.initialize_queue()

    # 4. Wavefront Naming
    print(">>> Phase 2: Naming Functions...")
    iteration = 0

    while True:
        batch = graph.get_batch(Config.BATCH_SIZE)
        if not batch: break  # Queue empty

        iteration += 1
        print(f"--- Wave {iteration}: {len(batch)} funcs ---")

        for node in batch:
            neighbor_ctx = {}
            for nid in node.callers.union(node.callees):
                if nid in graph.nodes and graph.nodes[nid].is_renamed:
                    neighbor_ctx[nid] = graph.nodes[nid].suggested_name

            # Analyze
            result = agent.analyze(node, neighbor_ctx)

            # Update Graph (This marks is_renamed=True if successful)
            graph.update_node(
                node.id,
                result["name"],
                result.get("confidence", "LOW"),
                result.get("reasoning", "No reasoning provided")
            )

            status = "RENAMED" if graph.nodes[node.id].is_renamed else "KEPT"
            print(f"   [{status}] {node.original_name} -> {result['name']}")

        # 5. Validation Phase (NEW)
        print("\n>>> Phase 3: Global Validation & Refinement...")
        validated_count = 0
        refined_count = 0

        # Create a list of nodes to validate to avoid dict size change issues
        nodes_to_validate = [n for n in graph.nodes.values() if n.is_renamed]

        from tqdm import tqdm
        for node in tqdm(nodes_to_validate):
            # Build COMPLETE context (now that everyone has a name)
            neighbor_ctx = {}
            for nid in node.callers.union(node.callees):
                if nid in graph.nodes and graph.nodes[nid].is_renamed:
                    neighbor_ctx[nid] = graph.nodes[nid].suggested_name

            # Ask Agent
            val_result = agent.validate_name(node, neighbor_ctx)

            # Apply Logic
            if val_result.get("is_valid") is False:
                better_name = val_result.get("better_name")
                if better_name and better_name != node.suggested_name:
                    print(f"   [REFINED] {node.suggested_name} -> {better_name}")
                    node.suggested_name = better_name
                    # Update Node State
                    node.suggested_name = better_name
                    node.reasoning += f" | Validation: {val_result.get('reason')}"
                    refined_count += 1

            validated_count += 1

        print(f"\n>>> Validation Complete. Refined {refined_count} names.")

    # 5. Output Results with Flags
    print("\n>>> Final Report")
    results = {}
    renamed_count = 0

    for nid, node in graph.nodes.items():
        results[nid] = {
            "original": node.original_name,
            "final_name": node.suggested_name,
            "is_renamed": node.is_renamed,
            "confidence": node.confidence,
            "reasoning": node.reasoning,
            "file": node.file_path
        }
        if node.is_renamed: renamed_count += 1

    print(f"Total Functions: {len(results)}")
    print(f"Renamed: {renamed_count}")

    with open("final_map.json", "w") as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
	
# WaveFunc: Agentic Auto-Namer for Decompiled Java

WaveFunc scans a Java repository (like decompiled Android APKs), parses the code using **Tree-Sitter**, builds a function call graph, and uses a **Wavefront LLM Algorithm** to iteratively rename obfuscated functions (`sub_xxx`) to meaningful names.

## Why "Wavefront"?
It names the easiest functions first (those with strings like "Password incorrect"). It then propagates these new names to their callers/callees, giving the AI context to name the harder functions in the next wave.

## Setup

1. **Install Dependencies**
   ```bash
   pip install tree-sitter tree-sitter-java litellm networkx tqdm
   
WaveFunc/
├── config.py             # Settings (API Keys, Models)
├── repo_parser.py        # The New Core: Tree-Sitter Logic
├── core_engine.py        # The Wavefront Algorithm
├── llm_agent.py          # The AI Worker
├── main.py               # Entry Point
├── utils.py              # Tree-Sitter Helpers
└── requirements.txt      # Dependencies


import os
import glob
from tree_sitter import Language, Parser
import tree_sitter_java
from utils import get_node_text, find_children_by_type
from config import Config
from tqdm import tqdm

class RepoParser:
    def __init__(self, root_dir: str):
        self.root_dir = root_dir
        self.JAVA_LANGUAGE = Language(tree_sitter_java.language())
        self.parser = Parser(self.JAVA_LANGUAGE)
        self.symbol_table = {}
        self.functions = {}

    def scan_repo(self):
        """Phase 1: Scan all files to build the Symbol Table."""
        print(f"[*] Scanning repository: {self.root_dir}")
        java_files = glob.glob(os.path.join(self.root_dir, "**/*.java"), recursive=True)

        for file_path in java_files:
            # Skip ignored directories
            if any(ign in file_path for ign in Config.IGNORE_DIRS):
                continue

            self._parse_file(file_path)

        print(f"[+] Found {len(self.functions)} functions.")
        print("[*] Resolving call graph (Phase 2)...")
        self._resolve_calls()

        return list(self.functions.values())

    def _parse_file(self, file_path):
        with open(file_path, 'rb') as f:
            source_bytes = f.read()

        tree = self.parser.parse(source_bytes)
        root_node = tree.root_node

        # 1. Identify Package
        package_name = ""
        pkg_node = root_node.child_by_field_name("package")
        if pkg_node:
            package_name = get_node_text(pkg_node.children[1], source_bytes)

        # 2. Find Class Declaration
        package_name = ""
        for child in root_node.children:
            if child.type == 'package_declaration':
                package_name = get_node_text(child.children[1], source_bytes)
                break

        # 2. Walk the tree recursively
        self._walk_classes(root_node, package_name, source_bytes, file_path)

    def _walk_classes(self, node, package, source, file_path):
        """Recursive walk to find classes and methods."""
        if node.type == 'class_declaration':
            class_name_node = node.child_by_field_name('name')
            if not class_name_node: return
            class_name = get_node_text(class_name_node, source)
            full_class_name = f"{package}.{class_name}" if package else class_name

            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    if child.type == 'method_declaration':
                        self._extract_method(child, full_class_name, source, file_path)

        # Recurse (for inner classes)
        for child in node.children:
            self._walk_classes(child, package, source, file_path)

    def _extract_method(self, node, class_name, source, file_path):
        name_node = node.child_by_field_name('name')
        if not name_node: return
        func_name = get_node_text(name_node, source)

        # Skip constructors or standard overrides if desired
        if func_name == class_name.split('.')[-1]: return

        # Create ID: com.package.Class.methodName
        func_id = f"{class_name}.{func_name}"

        # Extract Features immediately
        features = self._analyze_body(node, source)

        self.functions[func_id] = {
            "id": func_id,
            "name": func_name,
            "class": class_name,
            "file": file_path,
            "node": node,  # Keep reference if needed
            "features": features
        }

        # Register in symbol table for linking
        # Key: methodName (simple) -> List of potential full IDs
        if func_name not in self.symbol_table:
            self.symbol_table[func_name] = []
        self.symbol_table[func_name].append(func_id)

    def _analyze_body(self, method_node, source):
        features = {
            "strings": set(),
            "api_calls": set(),
            "internal_calls_raw": set()  # Unresolved method names
        }

        # Query for Method Calls and Strings
        query = self.JAVA_LANGUAGE.query("""
            (method_invocation name: (identifier) @call_name)
            (string_literal) @str_val
        """)

        captures = query.captures(method_node)

        # --- FIX STARTS HERE ---
        # Iterate over the dictionary: { 'capture_name': [Node, Node, ...] }
        for capture_name, nodes in captures.items():
            for node in nodes:
                text = get_node_text(node, source)

                if capture_name == 'str_val':
                    # Strip quotes
                    if len(text) >= 2:
                        clean_str = text[1:-1]
                        if len(clean_str) > 3 and " " not in clean_str:
                            features['strings'].add(clean_str)

                elif capture_name == 'call_name':
                    features['internal_calls_raw'].add(text)

                    # Try to get object called on (e.g., 'obj.method()')
                    # Parent is method_invocation, child 'object'
                    parent = node.parent
                    if parent:
                        obj_node = parent.child_by_field_name('object')
                        if obj_node:
                            obj_text = get_node_text(obj_node, source)
                            # Heuristic: If object starts with uppercase, it might be a static API call
                            if obj_text and obj_text[0].isupper():
                                features['api_calls'].add(f"{obj_text}.{text}")

        return features

    def _resolve_calls(self):
        """Phase 2: Link 'internal_calls_raw' to actual Function IDs."""
        for func in self.functions.values():
            func['features']['callees'] = set()

            for call_name in func['features']['internal_calls_raw']:
                # Lookup in symbol table
                if call_name in self.symbol_table:
                    potential_matches = self.symbol_table[call_name]

                    # Simple Heuristic: If only one match, link it.
                    # If multiple, checking imports is hard without full semantic analysis.
                    # We will link ALL of them as 'potential' edges.
                    # The Ripple Algorithm handles fuzzy edges well (context is additive).
                    for match_id in potential_matches:
                        # Don't link recursive calls
                        if match_id != func['id']:
                            func['features']['callees'].add(match_id)

            # Convert sets to lists
            func['features']['strings'] = list(func['features']['strings'])
            func['features']['api_calls'] = list(func['features']['api_calls'])
            func['features']['callees'] = list(func['features']['callees'])
            del func['features']['internal_calls_raw']

    def enrich_functions(self, agent):
        """
        NEW: Iterate over all found functions and use LLM to get semantic summary.
        """
        print(f"[*] Phase 1.5: Enriching {len(self.functions)} functions with Semantic Data...")

        # We read the files again to get the text bodies
        # This is slightly inefficient but safer than keeping all code in RAM
        for func in tqdm(self.functions.values()):
            # If it's a tiny function, skip LLM to save time/tokens?
            # User said "ALL", so we do all.

            with open(func['file'], 'rb') as f:
                f.seek(func['node'].start_byte)
                # Read just enough bytes
                length = func['node'].end_byte - func['node'].start_byte
                code_bytes = f.read(length)
                code_text = code_bytes.decode('utf-8', errors='ignore')

            # Ask LLM to summarize logic
            summary = agent.summarize_code(code_text)
            func['features']['semantic_summary'] = summary
			
			
tree-sitter>=0.23.0
tree-sitter-java>=0.23.0
litellm>=1.40.0
networkx>=3.1
tqdm

from tree_sitter import Node

def get_node_text(node: Node, source_bytes: bytes) -> str:
    """Extract text from a specific node."""
    return source_bytes[node.start_byte:node.end_byte].decode('utf-8')

def find_children_by_type(node: Node, type_name: str) -> list[Node]:
    """Return all direct children of a specific type."""
    return [child for child in node.children if child.type == type_name]

def clean_type_name(type_str: str) -> str:
    """Clean Java types (e.g., 'java.lang.String' -> 'String')."""
    if '<' in type_str: # Remove generics
        type_str = type_str.split('<')[0]
    return type_str.split('.')[-1]
