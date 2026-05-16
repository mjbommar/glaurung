package com.glaurung.jvmtool;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jetbrains.java.decompiler.main.decompiler.ConsoleDecompiler;

public final class Main {
    private Main() {}

    public static void main(String[] argv) {
        Map<String, Object> result;
        try {
            result = run(argv);
        } catch (Throwable exc) {
            result = error(exc);
        }
        System.out.println(Json.write(result));
        Object success = result.get("success");
        if (Boolean.FALSE.equals(success)) {
            System.exit(1);
        }
    }

    static Map<String, Object> run(String[] argv) throws Exception {
        Args args = Args.parse(argv);
        return switch (args.command) {
            case "version" -> version();
            case "bytecode" -> bytecode(args);
            case "decompile" -> decompile(args);
            case "parse-source" -> parseSource(args);
            default -> throw new IllegalArgumentException("unknown command: " + args.command);
        };
    }

    private static Map<String, Object> version() {
        Map<String, Object> out = base("version");
        out.put("success", true);
        out.put("tool", "glaurung-jvm-tools");
        out.put("java_version", System.getProperty("java.version"));
        out.put("engines", List.of("cfr", "vineflower"));
        out.put("vineflower_version", ConsoleDecompiler.version());
        return out;
    }

    private static Map<String, Object> bytecode(Args args) throws Exception {
        Path jarPath = Path.of(args.require("jar"));
        String className = args.require("class");
        byte[] bytes = ClassInputs.readClassBytes(jarPath, className);
        Map<String, Object> out = base("bytecode");
        out.put("success", true);
        out.put("archive_path", jarPath.toString());
        out.putAll(BytecodeSummary.summarize(bytes));
        return out;
    }

    private static Map<String, Object> decompile(Args args) throws Exception {
        Path jarPath = Path.of(args.require("jar"));
        String className = args.require("class");
        String engine = args.get("engine", "auto");
        int maxSourceChars = args.getInt("max-source-chars", 0);
        Map<String, Object> out = base("decompile");
        out.put("archive_path", jarPath.toString());
        out.putAll(Decompiler.decompile(jarPath, className, engine));
        if (maxSourceChars > 0) {
            String source = (String) out.getOrDefault("source", "");
            if (source.length() > maxSourceChars) {
                out.put("source", source.substring(0, maxSourceChars));
                out.put("source_truncated", true);
            } else {
                out.put("source_truncated", false);
            }
        }
        return out;
    }

    private static Map<String, Object> parseSource(Args args) throws Exception {
        Path sourcePath = Path.of(args.require("source"));
        String source = Files.readString(sourcePath, StandardCharsets.UTF_8);
        Map<String, Object> out = base("parse-source");
        out.put("success", true);
        out.put("source_path", sourcePath.toString());
        out.put("ast", AstSummary.fromSource(source));
        return out;
    }

    private static Map<String, Object> base(String command) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("command", command);
        return out;
    }

    private static Map<String, Object> error(Throwable exc) {
        Map<String, Object> out = base("error");
        out.put("success", false);
        out.put("error_type", exc.getClass().getName());
        out.put("message", exc.getMessage());
        out.put("stop_reasons", List.of("helper_exception"));
        return out;
    }
}
