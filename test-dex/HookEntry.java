package spec.inject;

public final class HookEntry {
    static {
        ClassLoader self = HookEntry.class.getClassLoader();
        ClassLoader ctx = Thread.currentThread().getContextClassLoader();
        log("HookEntry <clinit> pid=" + androidPid()
                + " selfLoader=" + name(self)
                + " ctxLoader=" + name(ctx)
                + " same=" + (self == ctx));
        try {
            Class<?> app = Class.forName("android.app.Application", false, self);
            log("resolved " + app.getName() + " via self loader");
        } catch (Throwable t) {
            log("Application resolve failed: " + t);
        }
    }

    private static String name(ClassLoader loader) {
        return loader == null ? "null" : loader.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(loader));
    }

    private static int androidPid() {
        try {
            Class<?> process = Class.forName("android.os.Process");
            return (Integer) process.getMethod("myPid").invoke(null);
        } catch (Throwable ignored) {
            return 0;
        }
    }

    private static void log(String msg) {
        try {
            Class<?> log = Class.forName("android.util.Log");
            log.getMethod("i", String.class, String.class).invoke(null, "SpecDex", msg);
        } catch (Throwable ignored) {
            System.out.println("SpecDex: " + msg);
        }
    }
}
