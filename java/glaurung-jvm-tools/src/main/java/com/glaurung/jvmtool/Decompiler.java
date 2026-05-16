package com.glaurung.jvmtool;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.benf.cfr.reader.api.CfrDriver;
import org.benf.cfr.reader.api.OutputSinkFactory;
import org.benf.cfr.reader.api.SinkReturns;
import org.jetbrains.java.decompiler.main.decompiler.ConsoleDecompiler;

final class Decompiler {
    private Decompiler() {}

    static Map<String, Object> decompile(Path jarPath, String className, String requestedEngine)
            throws IOException {
        String engine = ClassInputs.engine(requestedEngine);
        if (engine.equals("auto")) {
            engine = "cfr";
        }
        byte[] bytes = ClassInputs.readClassBytes(jarPath, className);
        String parsedClassName = ClassInputs.classNameFromBytes(bytes);
        Path classFile = ClassInputs.writeTempClass(bytes, parsedClassName);
        Path tempRoot = classFile;
        while (tempRoot.getParent() != null && !tempRoot.getFileName().toString().startsWith("glaurung-jvm-class-")) {
            tempRoot = tempRoot.getParent();
        }
        try {
            Map<String, Object> result =
                    switch (engine) {
                        case "cfr" -> decompileWithCfr(classFile);
                        case "vineflower" -> decompileWithVineflower(classFile);
                        default -> throw new IllegalArgumentException("unsupported engine: " + requestedEngine);
                    };
            result.put("engine", engine);
            result.put("class_name", parsedClassName);
            String source = (String) result.getOrDefault("source", "");
            result.put("source_length", source.length());
            result.put("ast", source.isBlank() ? Map.of("parse_success", false) : AstSummary.fromSource(source));
            return result;
        } finally {
            ClassInputs.deleteTree(tempRoot);
        }
    }

    private static Map<String, Object> decompileWithCfr(Path classFile) {
        List<String> sources = new ArrayList<>();
        List<String> diagnostics = new ArrayList<>();
        OutputSinkFactory sinkFactory = new OutputSinkFactory() {
            @Override
            public List<SinkClass> getSupportedSinks(SinkType sinkType, Collection<SinkClass> sinkClasses) {
                if (sinkType == SinkType.JAVA) {
                    return List.of(SinkClass.DECOMPILED, SinkClass.STRING);
                }
                if (sinkType == SinkType.EXCEPTION) {
                    return List.of(SinkClass.EXCEPTION_MESSAGE, SinkClass.STRING);
                }
                return List.of(SinkClass.STRING);
            }

            @Override
            @SuppressWarnings("unchecked")
            public <T> Sink<T> getSink(SinkType sinkType, SinkClass sinkClass) {
                return value -> {
                    if (sinkType == SinkType.JAVA && value instanceof SinkReturns.Decompiled decompiled) {
                        sources.add(decompiled.getJava());
                    } else if (sinkType == SinkType.JAVA && value instanceof String string) {
                        sources.add(string);
                    } else if (sinkType == SinkType.EXCEPTION) {
                        diagnostics.add(String.valueOf(value));
                    }
                };
            }
        };
        Map<String, String> options = new LinkedHashMap<>();
        options.put("silent", "true");
        CfrDriver driver = new CfrDriver.Builder().withOptions(options).withOutputSink(sinkFactory).build();
        driver.analyse(List.of(classFile.toString()));
        String source = String.join("\n", sources).strip();
        return result(!source.isBlank(), source, diagnostics);
    }

    private static Map<String, Object> decompileWithVineflower(Path classFile) throws IOException {
        Path outputDir = Files.createTempDirectory("glaurung-vineflower-");
        ByteArrayOutputStream logBytes = new ByteArrayOutputStream();
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        try (PrintStream capture = new PrintStream(logBytes, true, StandardCharsets.UTF_8)) {
            System.setOut(capture);
            System.setErr(capture);
            ConsoleDecompiler.main(new String[] {"-log=ERROR", classFile.toString(), outputDir.toString()});
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
        try {
            List<Path> sources;
            try (var stream = Files.walk(outputDir)) {
                sources = stream.filter(path -> path.toString().endsWith(".java"))
                        .sorted(Comparator.comparing(Path::toString))
                        .toList();
            }
            String source = "";
            if (!sources.isEmpty()) {
                source = Files.readString(sources.get(0), StandardCharsets.UTF_8).strip();
            }
            List<String> diagnostics = new ArrayList<>();
            String logs = logBytes.toString(StandardCharsets.UTF_8);
            if (!logs.isBlank()) {
                diagnostics.add(logs.strip());
            }
            return result(!source.isBlank(), source, diagnostics);
        } finally {
            ClassInputs.deleteTree(outputDir);
        }
    }

    private static Map<String, Object> result(boolean success, String source, List<String> diagnostics) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", success);
        out.put("source", source);
        out.put("diagnostics", diagnostics);
        out.put("diagnostic_count", diagnostics.size());
        if (!success && diagnostics.isEmpty()) {
            out.put("stop_reasons", List.of("decompiler_returned_no_source"));
        } else {
            out.put("stop_reasons", List.of());
        }
        return out;
    }
}
