package byw.bypass.devsniffer;

import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.NetworkCapabilities;
import android.provider.Settings;

import java.io.File;
import java.io.IOException;
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

    private static final Set<String> BLOCKED_PACKAGES = new HashSet<String>(Arrays.asList(
            "com.emanuelef.remote_capture",
            "com.pcapdroid.mitm",
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
            "hk.kirk.trustme",
            "com.virb3.trustmealready",
            "just.trust.me",
            "com.evozi.injector"
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
            "/proc/modules"
    ));

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam.packageName == null || lpparam.packageName.equals("android")) {
            return;
        }

        XposedBridge.log("[bywZero] Initializing Dev & Sniffer Bypass for: " + lpparam.packageName);

        hookCrashSuppression();
        hookSettings(lpparam.classLoader);
        hookPackageManager(lpparam.classLoader);
        hookNetworkCapabilities(lpparam.classLoader);
        hookRootFiles(lpparam.classLoader);

        if ("com.halcon.connect".equals(lpparam.packageName)) {
            hookHalconConnect(lpparam.classLoader);
        } else if ("mx.com.cfe.cfecontigo".equals(lpparam.packageName)) {
            hookCfeContigo(lpparam.classLoader);
        }
    }

    private void hookCrashSuppression() {
        try {
            wrapDefaultExceptionHandler();

            XposedHelpers.findAndHookMethod(Thread.class, "setDefaultUncaughtExceptionHandler", Thread.UncaughtExceptionHandler.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    final Thread.UncaughtExceptionHandler orig = (Thread.UncaughtExceptionHandler) param.args[0];
                    if (orig == null) return;
                    param.args[0] = createSafeHandler(orig);
                }
            });
        } catch (Throwable t) {
            XposedBridge.log("[bywZero] hookCrashSuppression error: " + t.getMessage());
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
                    XposedBridge.log("[bywZero] Suppressed DexGuard crash on [" + t.getName() + "]: " + e.getClass().getName() + " - " + e.getMessage());
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
        String msg = e.getMessage();
        if (msg != null && (msg.contains("divide by zero") || msg.contains("/ by zero"))) {
            return true;
        }
        StackTraceElement[] traces = e.getStackTrace();
        if (traces != null) {
            for (StackTraceElement ste : traces) {
                String cls = ste.getClassName();
                if (cls.startsWith("o.oood") || cls.startsWith("o.rrr") || cls.contains("behaviosec") || cls.contains("threatmetrix")) {
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
            XposedBridge.log("[bywZero] hookSettings error: " + t.getMessage());
        }
    }

    private void hookPackageManager(ClassLoader classLoader) {
        try {
            Class<?> pmClass = XposedHelpers.findClassIfExists("android.app.ApplicationPackageManager", classLoader);
            if (pmClass == null) return;

            XC_MethodHook pkgInfoHook = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    String pkg = (String) param.args[0];
                    if (pkg != null && BLOCKED_PACKAGES.contains(pkg)) {
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

            XposedHelpers.findAndHookMethod(pmClass, "getInstalledPackages", int.class, new XC_MethodHook() {
                @Override
                @SuppressWarnings("unchecked")
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    List<PackageInfo> list = (List<PackageInfo>) param.getResult();
                    if (list != null) {
                        List<PackageInfo> filtered = new ArrayList<PackageInfo>();
                        for (PackageInfo pi : list) {
                            if (pi != null && !BLOCKED_PACKAGES.contains(pi.packageName)) {
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
                            if (ai != null && !BLOCKED_PACKAGES.contains(ai.packageName)) {
                                filtered.add(ai);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });

        } catch (Throwable t) {
            XposedBridge.log("[bywZero] hookPackageManager error: " + t.getMessage());
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
            XposedBridge.log("[bywZero] hookNetworkCapabilities error: " + t.getMessage());
        }
    }

    private void hookRootFiles(ClassLoader classLoader) {
        try {
            XposedHelpers.findAndHookMethod(File.class, "exists", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    File file = (File) param.thisObject;
                    if (file != null) {
                        String path = file.getAbsolutePath();
                        if (ROOT_FILES.contains(path) || (path.startsWith("/data/adb/") && !path.startsWith("/data/adb/service.d"))) {
                            param.setResult(Boolean.FALSE);
                        }
                    }
                }
            });
        } catch (Throwable t) {
            XposedBridge.log("[bywZero] hookRootFiles error: " + t.getMessage());
        }
    }

    private void hookHalconConnect(ClassLoader classLoader) {
        try {
            Class<?> secClass = XposedHelpers.findClassIfExists("halcon.vip.vpn.util.NativeSecurity", classLoader);
            if (secClass != null) {
                XposedHelpers.findAndHookMethod(secClass, "checkSecurity", Context.class, XC_MethodReplacement.returnConstant(Integer.valueOf(0)));
                XposedBridge.log("[bywZero] Hooked halcon NativeSecurity.checkSecurity -> 0");
            }

            Class<?> bClass = XposedHelpers.findClassIfExists("v3.b", classLoader);
            if (bClass != null) {
                XposedHelpers.findAndHookMethod(bClass, "m", Context.class, XC_MethodReplacement.returnConstant(Boolean.TRUE));
                XposedBridge.log("[bywZero] Hooked halcon v3.b.m -> true");
            }
        } catch (Throwable t) {
            XposedBridge.log("[bywZero] hookHalconConnect error: " + t.getMessage());
        }
    }

    private void hookCfeContigo(ClassLoader classLoader) {
        try {
            Class<?> sClass = XposedHelpers.findClassIfExists("o.s00730073s00730073s", classLoader);
            if (sClass != null) {
                XposedHelpers.findAndHookMethod(sClass, "MediaBrowserCompatCustomActionResultReceiver", XC_MethodReplacement.returnConstant(Boolean.TRUE));
                XposedBridge.log("[bywZero] Hooked CFE s00730073s00730073s.MediaBrowserCompatCustomActionResultReceiver -> true");
            } else {
                XposedBridge.log("[bywZero] CFE class o.s00730073s00730073s not found!");
            }
        } catch (Throwable t) {
            XposedBridge.log("[bywZero] hookCfeContigo error: " + t.getMessage());
        }
    }
}
