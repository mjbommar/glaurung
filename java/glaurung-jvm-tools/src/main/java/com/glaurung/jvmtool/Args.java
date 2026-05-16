package com.glaurung.jvmtool;

import java.util.LinkedHashMap;
import java.util.Map;

final class Args {
    final String command;
    final Map<String, String> options;

    private Args(String command, Map<String, String> options) {
        this.command = command;
        this.options = options;
    }

    static Args parse(String[] argv) {
        if (argv.length == 0) {
            throw new IllegalArgumentException("missing command");
        }
        Map<String, String> options = new LinkedHashMap<>();
        int i = 1;
        while (i < argv.length) {
            String token = argv[i];
            if (!token.startsWith("--")) {
                throw new IllegalArgumentException("unexpected argument: " + token);
            }
            String key = token.substring(2);
            if (key.isBlank()) {
                throw new IllegalArgumentException("empty option name");
            }
            if (i + 1 >= argv.length || argv[i + 1].startsWith("--")) {
                options.put(key, "true");
                i++;
            } else {
                options.put(key, argv[i + 1]);
                i += 2;
            }
        }
        return new Args(argv[0], options);
    }

    String require(String key) {
        String value = options.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("missing required option --" + key);
        }
        return value;
    }

    String get(String key, String defaultValue) {
        String value = options.get(key);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    int getInt(String key, int defaultValue) {
        String value = options.get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return Integer.parseInt(value);
    }
}
