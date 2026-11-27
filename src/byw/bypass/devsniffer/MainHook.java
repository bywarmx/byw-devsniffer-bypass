package byw.bypass.devsniffer;

import android.app.ActivityManager;
import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.NetworkCapabilities;
import android.os.Process;
import android.provider.Settings;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class MainHook implements IXposedHookLoadPackage {

    private static final String TAG = "bywZero";

    private static final Set<String> BLOCKED_PACKAGES = new HashSet<String>(Arrays.asList(
            "com.emanuelef.remote_capture",
            "com.pcapdroid.mitm",
            "com.byw.pwardroid",
            "com.byw.netmanager",
            "app.greyshirts.sslcapture",
            "com.guoshi.httpcanary",
            "com.guoshi.httpcanary.premium",
            "com.minhui.networkcapture",
            "com.minhui.networkcapture.pro",
            "jp.co.taosoftware.android.packetcapture",
            "de.robv.android.xposed.installer",
            "io.va.exposed",
            "org.matrix.vector.manager",
            "org.lsposed.manager",
            "me.weishu.kernelsu",
            "com.topjohnwu.magisk",
            "ru.dxqlyhmv.eyyuacuyb",
            "com.joeykrim.rootcheck",
            "hk.kirk.trustme",
            "com.virb3.trustmealready",
            "just.trust.me"
    ));

    private static final Set<String> ROOT_FILES = new HashSet<String>(Arrays.asList(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/app/SuperSU",
            "/system/app/Superuser",
            "/system/xbin/daemonsu",
            "/system/etc/init.d/99SuperSUDaemon",
            "/system/bin/.ext/.su",
            "/system/etc/.has_su_daemon",
            "/system/etc/.installed_su_daemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/data/adb/ksu",
            "/data/adb/ksud",
            "/data/adb/magisk",
            "/data/adb/modules",
            "/proc/modules",
            "/system/bin/which",
            "/system/xbin/which"
    ));

    private static volatile boolean sSuppressedCrashRecently = false;

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam.packageName == null || lpparam.packageName.equals("android")) {
            return;
        }

        Log.e(TAG, "Initializing Dev & Sniffer Bypass for: " + lpparam.packageName);

        hookCrashSuppression(lpparam.packageName);
        hookSettings(lpparam.classLoader);
        hookPackageManager(lpparam.packageName, lpparam.classLoader);
        if (!"com.halcon.connect".equals(lpparam.packageName) && !"com.evozi.injector".equals(lpparam.packageName)) {
            hookNetworkCapabilities(lpparam.classLoader);
        }
        hookRootFiles(lpparam.packageName, lpparam.classLoader);

        if ("com.halcon.connect".equals(lpparam.packageName)) {
            hookHalconConnect(lpparam.classLoader);
        } else if ("com.evozi.injector".equals(lpparam.packageName)) {
            hookHttpInjector(lpparam.classLoader);
        } else if ("mx.com.cfe.cfecontigo".equals(lpparam.packageName)) {
            hookCfeContigo(lpparam.classLoader);
        }
    }

    private void hookCrashSuppression(final String hostPackage) {
        try {
            wrapDefaultExceptionHandler();

            XposedHelpers.findAndHookMethod(Thread.class, "getUncaughtExceptionHandler", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    final Thread.UncaughtExceptionHandler original = (Thread.UncaughtExceptionHandler) param.getResult();
                    param.setResult(createSafeHandler(original));
                }
            });

            XposedHelpers.findAndHookMethod(Thread.class, "setDefaultUncaughtExceptionHandler", Thread.UncaughtExceptionHandler.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    final Thread.UncaughtExceptionHandler orig = (Thread.UncaughtExceptionHandler) param.args[0];
                    if (orig == null) return;
                    param.args[0] = createSafeHandler(orig);
                }
            });

            XposedHelpers.findAndHookMethod(Thread.class, "setUncaughtExceptionHandler", Thread.UncaughtExceptionHandler.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    final Thread.UncaughtExceptionHandler orig = (Thread.UncaughtExceptionHandler) param.args[0];
                    if (orig == null) return;
                    param.args[0] = createSafeHandler(orig);
                }
            });

            XposedHelpers.findAndHookMethod(Process.class, "killProcess", int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    int pid = ((Integer) param.args[0]).intValue();
                    if (pid == Process.myPid()) {
                        Log.e(TAG, "Blocked self Process.killProcess in: " + hostPackage);
                        param.setResult(null);
                    }
                }
            });

            XposedHelpers.findAndHookMethod(System.class, "exit", int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (sSuppressedCrashRecently || "com.halcon.connect".equals(hostPackage) || "com.evozi.injector".equals(hostPackage)) {
                        Log.e(TAG, "Blocked System.exit in: " + hostPackage);
                        param.setResult(null);
                    }
                }
            });

        } catch (Throwable t) {
            Log.e(TAG, "hookCrashSuppression error: " + t.getMessage());
        }
    }

    private void wrapDefaultExceptionHandler() {
        try {
            final Thread.UncaughtExceptionHandler current = Thread.getDefaultUncaughtExceptionHandler();
            Thread.setDefaultUncaughtExceptionHandler(createSafeHandler(current));
        } catch (Throwable ignored) {}
    }

    private Thread.UncaughtExceptionHandler createSafeHandler(final Thread.UncaughtExceptionHandler original) {
        return new Thread.UncaughtExceptionHandler() {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                if (shouldSuppress(t, e)) {
                    sSuppressedCrashRecently = true;
                    Log.e(TAG, "SUPPRESSED CRASH via Handler on [" + (t != null ? t.getName() : "null") + "]: " + e);
                    return;
                }
                if (original != null) {
                    original.uncaughtException(t, e);
                }
            }
        };
    }

    private boolean shouldSuppress(Thread t, Throwable e) {
        if (e == null) return false;
        if (e instanceof ArithmeticException) {
            return true;
        }
        if (e instanceof UnsatisfiedLinkError) {
            String msg = e.getMessage();
            if (msg != null && (msg.contains("forcedark") || msg.contains("libforcedarkimpl.so"))) {
                return true;
            }
        }
        String msg = e.getMessage();
        if (msg != null && (msg.contains("divide by zero") || msg.contains("/ by zero") || msg.contains("zero") || msg.contains("1461490835"))) {
            return true;
        }
        StackTraceElement[] traces = e.getStackTrace();
        if (traces != null) {
            for (StackTraceElement ste : traces) {
                String cls = ste.getClassName();
                if (cls.startsWith("o.oood") || cls.startsWith("o.rrr") || cls.contains("behaviosec") || cls.contains("threatmetrix") || cls.contains("InitProvider") || cls.contains("ForceDark")) {
                    return true;
                }
            }
        }
        return false;
    }

    private void hookSettings(ClassLoader classLoader) {
        try {
            Class<?> globalClass = XposedHelpers.findClassIfExists("android.provider.Settings$Global", classLoader);
            if (globalClass != null) {
                XC_MethodHook intHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String name = (String) param.args[1];
                        if ("development_settings_enabled".equals(name) || "adb_enabled".equals(name)) {
                            param.setResult(Integer.valueOf(0));
                        }
                    }
                };

                XposedHelpers.findAndHookMethod(globalClass, "getInt", ContentResolver.class, String.class, int.class, intHook);
                XposedHelpers.findAndHookMethod(globalClass, "getInt", ContentResolver.class, String.class, intHook);

                XC_MethodHook strHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String name = (String) param.args[1];
                        if ("development_settings_enabled".equals(name) || "adb_enabled".equals(name)) {
                            param.setResult("0");
                        }
                    }
                };

                XposedHelpers.findAndHookMethod(globalClass, "getString", ContentResolver.class, String.class, strHook);
            }

            Class<?> secureClass = XposedHelpers.findClassIfExists("android.provider.Settings$Secure", classLoader);
            if (secureClass != null) {
                XC_MethodHook secureIntHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        String name = (String) param.args[1];
                        if ("development_settings_enabled".equals(name) || "adb_enabled".equals(name)) {
                            param.setResult(Integer.valueOf(0));
                        }
                    }
                };

                XposedHelpers.findAndHookMethod(secureClass, "getInt", ContentResolver.class, String.class, int.class, secureIntHook);
                XposedHelpers.findAndHookMethod(secureClass, "getInt", ContentResolver.class, String.class, secureIntHook);
            }
        } catch (Throwable t) {
            Log.e(TAG, "hookSettings error: " + t.getMessage());
        }
    }

    private void hookPackageManager(final String hostPackage, ClassLoader classLoader) {
        try {
            Class<?> pmClass = XposedHelpers.findClassIfExists("android.app.ApplicationPackageManager", classLoader);
            if (pmClass == null) return;

            XC_MethodHook pkgInfoHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String pkg = (String) param.args[0];
                    if (pkg != null && !pkg.equals(hostPackage) && BLOCKED_PACKAGES.contains(pkg)) {
                        param.setThrowable(new PackageManager.NameNotFoundException(pkg));
                    }
                }
            };

            try {
                XposedHelpers.findAndHookMethod(pmClass, "getPackageInfo", String.class, int.class, pkgInfoHook);
            } catch (Throwable ignored) {}

            try {
                Class<?> flagsClass = XposedHelpers.findClassIfExists("android.content.pm.PackageManager$PackageInfoFlags", classLoader);
                if (flagsClass != null) {
                    XposedHelpers.findAndHookMethod(pmClass, "getPackageInfo", String.class, flagsClass, pkgInfoHook);
                }
            } catch (Throwable ignored) {}

            try {
                XposedHelpers.findAndHookMethod(pmClass, "getApplicationInfo", String.class, int.class, pkgInfoHook);
            } catch (Throwable ignored) {}

            try {
                Class<?> appFlagsClass = XposedHelpers.findClassIfExists("android.content.pm.PackageManager$ApplicationInfoFlags", classLoader);
                if (appFlagsClass != null) {
                    XposedHelpers.findAndHookMethod(pmClass, "getApplicationInfo", String.class, appFlagsClass, pkgInfoHook);
                }
            } catch (Throwable ignored) {}

            XposedHelpers.findAndHookMethod(pmClass, "getInstalledPackages", int.class, new XC_MethodHook() {
                @Override
                @SuppressWarnings("unchecked")
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    List<PackageInfo> list = (List<PackageInfo>) param.getResult();
                    if (list != null) {
                        List<PackageInfo> filtered = new ArrayList<PackageInfo>();
                        for (PackageInfo pi : list) {
                            if (pi != null && (pi.packageName.equals(hostPackage) || !BLOCKED_PACKAGES.contains(pi.packageName))) {
                                filtered.add(pi);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            XposedHelpers.findAndHookMethod(pmClass, "getInstalledApplications", int.class, new XC_MethodHook() {
                @Override
                @SuppressWarnings("unchecked")
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    List<ApplicationInfo> list = (List<ApplicationInfo>) param.getResult();
                    if (list != null) {
                        List<ApplicationInfo> filtered = new ArrayList<ApplicationInfo>();
                        for (ApplicationInfo ai : list) {
                            if (ai != null && (ai.packageName.equals(hostPackage) || !BLOCKED_PACKAGES.contains(ai.packageName))) {
                                filtered.add(ai);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

            Class<?> amClass = XposedHelpers.findClassIfExists("android.app.ActivityManager", classLoader);
            if (amClass != null) {
                try {
                    XposedHelpers.findAndHookMethod(amClass, "getRunningAppProcesses", new XC_MethodHook() {
                        @Override
                        @SuppressWarnings("unchecked")
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            List<ActivityManager.RunningAppProcessInfo> list = (List<ActivityManager.RunningAppProcessInfo>) param.getResult();
                            if (list != null) {
                                List<ActivityManager.RunningAppProcessInfo> filtered = new ArrayList<ActivityManager.RunningAppProcessInfo>();
                                for (ActivityManager.RunningAppProcessInfo info : list) {
                                    if (info != null && info.processName != null) {
                                        if (info.processName.contains(hostPackage)) {
                                            filtered.add(info);
                                            continue;
                                        }
                                        if (!BLOCKED_PACKAGES.contains(info.processName)) {
                                            boolean blocked = false;
                                            if (info.pkgList != null) {
                                                for (String p : info.pkgList) {
                                                    if (!p.equals(hostPackage) && BLOCKED_PACKAGES.contains(p)) {
                                                        blocked = true;
                                                        break;
                                                    }
                                                }
                                            }
                                            if (!blocked) {
                                                filtered.add(info);
                                            }
                                        }
                                    }
                                }
                                param.setResult(filtered);
                            }
                        }
                    });
                } catch (Throwable ignored) {}

                try {
                    XposedHelpers.findAndHookMethod(amClass, "getRunningServices", int.class, new XC_MethodHook() {
                        @Override
                        @SuppressWarnings("unchecked")
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            List<ActivityManager.RunningServiceInfo> list = (List<ActivityManager.RunningServiceInfo>) param.getResult();
                            if (list != null) {
                                List<ActivityManager.RunningServiceInfo> filtered = new ArrayList<ActivityManager.RunningServiceInfo>();
                                for (ActivityManager.RunningServiceInfo s : list) {
                                    if (s != null && s.service != null) {
                                        if (s.service.getPackageName().equals(hostPackage)) {
                                            filtered.add(s);
                                            continue;
                                        }
                                        if (!BLOCKED_PACKAGES.contains(s.service.getPackageName()) && !BLOCKED_PACKAGES.contains(s.process)) {
                                            filtered.add(s);
                                        }
                                    }
                                }
                                param.setResult(filtered);
                            }
                        }
                    });
                } catch (Throwable ignored) {}
            }

        } catch (Throwable t) {
            Log.e(TAG, "hookPackageManager error: " + t.getMessage());
        }
    }

    private void hookNetworkCapabilities(ClassLoader classLoader) {
        try {
            Class<?> netCapClass = XposedHelpers.findClassIfExists("android.net.NetworkCapabilities", classLoader);
            if (netCapClass != null) {
                XposedHelpers.findAndHookMethod(netCapClass, "hasTransport", int.class, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        int transport = ((Integer) param.args[0]).intValue();
                        if (transport == NetworkCapabilities.TRANSPORT_VPN) {
                            param.setResult(Boolean.FALSE);
                        }
                    }
                });
            }
        } catch (Throwable t) {
            Log.e(TAG, "hookNetworkCapabilities error: " + t.getMessage());
        }
    }

    private static boolean isRootPath(String path) {
        if (path == null) return false;
        if (ROOT_FILES.contains(path)) return true;
        if (path.contains("/su") || path.endsWith("/su") || path.contains("magisk") || path.contains("kernelsu") || path.contains("ksud")) {
            return true;
        }
        if (path.startsWith("/data/adb/") && !path.startsWith("/data/adb/service.d")) {
            return true;
        }
        return false;
    }

    private void hookRootFiles(final String hostPackage, ClassLoader classLoader) {
        try {
            XC_MethodHook fileHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    File file = (File) param.thisObject;
                    if (file != null) {
                        String path = file.getAbsolutePath();
                        if (isRootPath(path)) {
                            param.setResult(Boolean.FALSE);
                        }
                    }
                }
            };

            XposedHelpers.findAndHookMethod(File.class, "exists", fileHook);
            try {
                XposedHelpers.findAndHookMethod(File.class, "canExecute", fileHook);
                XposedHelpers.findAndHookMethod(File.class, "canRead", fileHook);
            } catch (Throwable ignored) {}

            // Hook Runtime.exec and ProcessBuilder to block command-based root checks, unless host app is HTTP Injector
            if (!"com.evozi.injector".equals(hostPackage)) {
                XC_MethodHook execHook = new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Object cmdObj = param.args[0];
                        String cmd = "";
                        if (cmdObj instanceof String) {
                            cmd = (String) cmdObj;
                        } else if (cmdObj instanceof String[]) {
                            cmd = Arrays.toString((String[]) cmdObj);
                        }
                        if (cmd.contains("su") || cmd.contains("which") || cmd.contains("busybox")) {
                            Log.e(TAG, "Blocked exec command: " + cmd);
                            param.setThrowable(new IOException("Command not found: " + cmd));
                        }
                    }
                };

                try {
                    XposedHelpers.findAndHookMethod(Runtime.class, "exec", String.class, execHook);
                    XposedHelpers.findAndHookMethod(Runtime.class, "exec", String[].class, execHook);
                    XposedHelpers.findAndHookMethod(Runtime.class, "exec", String.class, String[].class, File.class, execHook);
                    XposedHelpers.findAndHookMethod(Runtime.class, "exec", String[].class, String[].class, File.class, execHook);
                } catch (Throwable ignored) {}

                try {
                    XposedHelpers.findAndHookMethod(ProcessBuilder.class, "start", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                            ProcessBuilder pb = (ProcessBuilder) param.thisObject;
                            List<String> command = pb.command();
                            if (command != null) {
                                for (String c : command) {
                                    if (c != null && (c.contains("su") || c.contains("which") || c.contains("busybox"))) {
                                        Log.e(TAG, "Blocked ProcessBuilder command: " + command);
                                        param.setThrowable(new IOException("Command not found: " + command));
                                        return;
                                    }
                                }
                            }
                        }
                    });
                } catch (Throwable ignored) {}
            }

            try {
                Field tagsField = android.os.Build.class.getDeclaredField("TAGS");
                tagsField.setAccessible(true);
                tagsField.set(null, "release-keys");
            } catch (Throwable ignored) {}

        } catch (Throwable t) {
            Log.e(TAG, "hookRootFiles error: " + t.getMessage());
        }
    }

    private void hookHttpInjector(final ClassLoader classLoader) {
        try {
            Log.e(TAG, "Initialized HTTP Injector specific hooks");
        } catch (Throwable t) {
            Log.e(TAG, "hookHttpInjector error: " + t.getMessage());
        }
    }

    private void hookNativeSecurityMethods(Class<?> secClass) {
        try {
            for (Method m : secClass.getDeclaredMethods()) {
                if (m.getName().equals("checkSecurity")) {
                    XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(Integer.valueOf(0)));
                    Log.e(TAG, "Hooked NativeSecurity.checkSecurity -> 0");
                }
            }
        } catch (Throwable t) {
            Log.e(TAG, "hookNativeSecurityMethods error: " + t.getMessage());
        }
    }

    private void hookHalconConnect(final ClassLoader classLoader) {
        try {
            // 1. Hook NativeSecurity.checkSecurity directly
            Class<?> secClass = XposedHelpers.findClassIfExists("halcon.vip.vpn.util.NativeSecurity", classLoader);
            if (secClass != null) {
                hookNativeSecurityMethods(secClass);
            }

            // 3. Hook v3.b.m (security alert dialog trigger) -> return true
            Class<?> bClass = XposedHelpers.findClassIfExists("v3.b", classLoader);
            if (bClass != null) {
                for (Method m : bClass.getDeclaredMethods()) {
                    if (m.getName().equals("m") && m.getReturnType() == boolean.class) {
                        XposedBridge.hookMethod(m, XC_MethodReplacement.returnConstant(Boolean.TRUE));
                        Log.e(TAG, "Hooked halcon v3.b.m -> true");
                    }
                }
            }

            // 4. Hook m4.t.n (background termination check) -> DO_NOTHING
            Class<?> tClass = XposedHelpers.findClassIfExists("m4.t", classLoader);
            if (tClass != null) {
                for (Method m : tClass.getDeclaredMethods()) {
                    if (m.getName().equals("n")) {
                        XposedBridge.hookMethod(m, XC_MethodReplacement.DO_NOTHING);
                        Log.e(TAG, "Hooked halcon m4.t.n -> DO_NOTHING");
                    }
                }
            }

            // 5. Block Process.killProcess and System.exit within Halcon
            XposedHelpers.findAndHookMethod(Process.class, "killProcess", int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    int pid = ((Integer) param.args[0]).intValue();
                    if (pid == Process.myPid()) {
                        Log.e(TAG, "Halcon: Blocked Process.killProcess(myPid)");
                        param.setResult(null);
                    }
                }
            });

            XposedHelpers.findAndHookMethod(System.class, "exit", int.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Log.e(TAG, "Halcon: Blocked System.exit(" + param.args[0] + ")");
                    param.setResult(null);
                }
            });

        } catch (Throwable t) {
            Log.e(TAG, "hookHalconConnect error: " + t.getMessage());
        }
    }

    private void hookCfeContigo(final ClassLoader classLoader) {
        try {
            Class<?> sClass = XposedHelpers.findClassIfExists("o.s00730073s00730073s", classLoader);
            if (sClass != null) {
                XposedHelpers.findAndHookMethod(sClass, "MediaBrowserCompatCustomActionResultReceiver", XC_MethodReplacement.returnConstant(Boolean.TRUE));
                Log.e(TAG, "Hooked CFE s00730073s00730073s.MediaBrowserCompatCustomActionResultReceiver -> true");
            } else {
                Log.e(TAG, "CFE class o.s00730073s00730073s not found!");
            }

            // 1. Huawei AAID InitProvider
            Class<?> initProvClass = XposedHelpers.findClassIfExists("com.huawei.hms.aaid.InitProvider", classLoader);
            if (initProvClass != null) {
                XposedHelpers.findAndHookMethod(initProvClass, "onCreate", XC_MethodReplacement.returnConstant(Boolean.TRUE));
                Log.e(TAG, "Hooked CFE com.huawei.hms.aaid.InitProvider.onCreate -> true");
            }

            // 2. Firebase InitProvider
            Class<?> fbClass = XposedHelpers.findClassIfExists("com.google.firebase.provider.FirebaseInitProvider", classLoader);
            if (fbClass != null) {
                XposedHelpers.findAndHookMethod(fbClass, "onCreate", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            if (param.thisObject instanceof android.content.ContentProvider) {
                                Context ctx = ((android.content.ContentProvider) param.thisObject).getContext();
                                Class<?> fbApp = XposedHelpers.findClassIfExists("com.google.firebase.FirebaseApp", classLoader);
                                if (fbApp != null && ctx != null) {
                                    Method m = fbApp.getMethod("initializeApp", Context.class);
                                    m.invoke(null, ctx);
                                    Log.e(TAG, "Manually initialized FirebaseApp via reflection");
                                }
                            }
                        } catch (Throwable t) {
                            Log.e(TAG, "FirebaseApp.initializeApp error: " + t.getMessage());
                        }
                        param.setResult(Boolean.FALSE);
                    }
                });
                Log.e(TAG, "Hooked CFE FirebaseInitProvider.onCreate -> bypass DexGuard");
            }

            // 3. Huawei AGConnect InitializeProvider
            Class<?> agcProvClass = XposedHelpers.findClassIfExists("com.huawei.agconnect.core.provider.AGConnectInitializeProvider", classLoader);
            if (agcProvClass != null) {
                XposedHelpers.findAndHookMethod(agcProvClass, "onCreate", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        try {
                            if (param.thisObject instanceof android.content.ContentProvider) {
                                Context ctx = ((android.content.ContentProvider) param.thisObject).getContext();
                                Class<?> agc = XposedHelpers.findClassIfExists("com.huawei.agconnect.AGConnectInstance", classLoader);
                                if (agc != null && ctx != null) {
                                    Method m = agc.getMethod("initialize", Context.class);
                                    m.invoke(null, ctx);
                                    Log.e(TAG, "Manually initialized AGConnectInstance via reflection");
                                }
                            }
                        } catch (Throwable t) {
                            Log.e(TAG, "AGConnectInstance.initialize error: " + t.getMessage());
                        }
                        param.setResult(Boolean.FALSE);
                    }
                });
                Log.e(TAG, "Hooked CFE AGConnectInitializeProvider.onCreate -> bypass DexGuard");
            }

            // 4. Huawei Push Provider
            Class<?> pushProvClass = XposedHelpers.findClassIfExists("com.huawei.hms.support.api.push.PushProvider", classLoader);
            if (pushProvClass != null) {
                XposedHelpers.findAndHookMethod(pushProvClass, "onCreate", XC_MethodReplacement.returnConstant(Boolean.TRUE));
                Log.e(TAG, "Hooked CFE PushProvider.onCreate -> true");
            }

            // 5. AndroidX FileProvider
            Class<?> fileProvClass = XposedHelpers.findClassIfExists("androidx.core.content.FileProvider", classLoader);
            if (fileProvClass != null) {
                XposedHelpers.findAndHookMethod(fileProvClass, "onCreate", XC_MethodReplacement.returnConstant(Boolean.TRUE));
                Log.e(TAG, "Hooked CFE FileProvider.onCreate -> true");
            }

        } catch (Throwable t) {
            Log.e(TAG, "hookCfeContigo error: " + t.getMessage());
        }
    }
}
