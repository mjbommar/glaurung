package com.glaurung.jvmtool;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Locale;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import org.objectweb.asm.ClassReader;

final class ClassInputs {
    private ClassInputs() {}

    static String normalizeClassName(String className) {
        String normalized = className.replace('.', '/');
        if (normalized.endsWith(".class")) {
            normalized = normalized.substring(0, normalized.length() - ".class".length());
        }
        while (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        return normalized;
    }

    static byte[] readClassBytes(Path jarPath, String className) throws IOException {
        String entryName = normalizeClassName(className) + ".class";
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            ZipEntry entry = jar.getEntry(entryName);
            if (entry == null) {
                throw new IOException("class entry not found: " + entryName);
            }
            try (InputStream input = jar.getInputStream(entry)) {
                return input.readAllBytes();
            }
        }
    }

    static String classNameFromBytes(byte[] bytes) {
        return new ClassReader(bytes).getClassName();
    }

    static Path writeTempClass(byte[] bytes, String className) throws IOException {
        Path root = Files.createTempDirectory("glaurung-jvm-class-");
        Path classFile = root.resolve(normalizeClassName(className) + ".class");
        Files.createDirectories(classFile.getParent());
        Files.write(classFile, bytes);
        return classFile;
    }

    static void deleteTree(Path root) {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try {
            Files.walk(root)
                    .sorted(Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (IOException ignored) {
                            // Best-effort cleanup only.
                        }
                    });
        } catch (IOException ignored) {
            // Best-effort cleanup only.
        }
    }

    static String engine(String value) {
        return value.toLowerCase(Locale.ROOT);
    }
}
