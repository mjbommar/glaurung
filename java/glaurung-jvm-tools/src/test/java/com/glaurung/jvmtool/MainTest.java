package com.glaurung.jvmtool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.spi.ToolProvider;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MainTest {
    @TempDir
    Path tmp;

    @Test
    void bytecodeSummarizesGeneratedClass() throws Exception {
        Path jar = fixtureJar();

        Map<String, Object> result =
                Main.run(new String[] {"bytecode", "--jar", jar.toString(), "--class", "app.Main"});

        assertEquals(true, result.get("success"));
        assertEquals("app/Main", result.get("class_name"));
        assertEquals(1, result.get("field_count"));
        assertTrue((Integer) result.get("method_count") >= 2);
    }

    @Test
    void cfrDecompilesGeneratedClassAndJavaParserSummarizesIt() throws Exception {
        Path jar = fixtureJar();

        Map<String, Object> result =
                Main.run(new String[] {"decompile", "--jar", jar.toString(), "--class", "app.Main", "--engine", "cfr"});

        assertEquals(true, result.get("success"));
        String source = (String) result.get("source");
        assertTrue(source.contains("class Main"));
        assertTrue(source.contains("field-constant"));
        @SuppressWarnings("unchecked")
        Map<String, Object> ast = (Map<String, Object>) result.get("ast");
        assertEquals(true, ast.get("parse_success"));
        assertEquals("app", ast.get("package_name"));
    }

    @Test
    void javaParserReportsSyntaxProblems() throws Exception {
        Path source = tmp.resolve("Broken.java");
        Files.writeString(source, "package app; public class Broken {", StandardCharsets.UTF_8);

        Map<String, Object> result =
                Main.run(new String[] {"parse-source", "--source", source.toString()});

        assertEquals(true, result.get("success"));
        @SuppressWarnings("unchecked")
        Map<String, Object> ast = (Map<String, Object>) result.get("ast");
        assertEquals(false, ast.get("parse_success"));
        assertFalse(((java.util.List<?>) ast.get("problems")).isEmpty());
    }

    private Path fixtureJar() throws IOException {
        Path sourceRoot = tmp.resolve("src");
        Path classes = tmp.resolve("classes");
        Files.createDirectories(sourceRoot.resolve("app"));
        Files.createDirectories(classes);
        Path source = sourceRoot.resolve("app/Main.java");
        Files.writeString(
                source,
                """
                package app;

                public class Main {
                    public static final String FIELD_CONST = "field-constant";

                    public String value() {
                        return "method-constant";
                    }
                }
                """,
                StandardCharsets.UTF_8);
        ToolProvider javac = ToolProvider.findFirst("javac").orElseThrow();
        int exit =
                javac.run(
                        System.out,
                        System.err,
                        "--release",
                        "17",
                        "-d",
                        classes.toString(),
                        source.toString());
        if (exit != 0) {
            throw new IOException("javac failed: " + exit);
        }
        Path jar = tmp.resolve("fixture.jar");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
            Path classFile = classes.resolve("app/Main.class");
            out.putNextEntry(new JarEntry("app/Main.class"));
            out.write(Files.readAllBytes(classFile));
            out.closeEntry();
        }
        return jar;
    }
}
