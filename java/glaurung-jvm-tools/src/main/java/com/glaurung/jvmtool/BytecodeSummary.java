package com.glaurung.jvmtool;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.MethodNode;

final class BytecodeSummary {
    private BytecodeSummary() {}

    static Map<String, Object> summarize(byte[] bytes) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("class_name", node.name);
        out.put("super_name", node.superName);
        out.put("access", node.access);
        out.put("major_version", node.version & 0xFFFF);
        out.put("minor_version", (node.version >>> 16) & 0xFFFF);
        out.put("interface_count", node.interfaces.size());
        out.put("field_count", node.fields.size());
        out.put("method_count", node.methods.size());
        out.put("fields", fields(node.fields));
        out.put("methods", methods(node.methods));
        return out;
    }

    private static List<Map<String, Object>> fields(List<FieldNode> fields) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (FieldNode field : fields) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", field.name);
            item.put("descriptor", field.desc);
            item.put("access", field.access);
            out.add(item);
        }
        return out;
    }

    private static List<Map<String, Object>> methods(List<MethodNode> methods) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (MethodNode method : methods) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", method.name);
            item.put("descriptor", method.desc);
            item.put("access", method.access);
            item.put("instruction_count", method.instructions == null ? 0 : method.instructions.size());
            item.put("try_catch_block_count", method.tryCatchBlocks == null ? 0 : method.tryCatchBlocks.size());
            item.put("max_stack", method.maxStack);
            item.put("max_locals", method.maxLocals);
            addLineRange(item, method);
            out.add(item);
        }
        return out;
    }

    private static void addLineRange(Map<String, Object> item, MethodNode method) {
        Integer lineMin = null;
        Integer lineMax = null;
        int lineCount = 0;
        if (method.instructions != null) {
            for (AbstractInsnNode instruction : method.instructions) {
                if (instruction instanceof LineNumberNode line) {
                    lineCount++;
                    lineMin = lineMin == null ? line.line : Math.min(lineMin, line.line);
                    lineMax = lineMax == null ? line.line : Math.max(lineMax, line.line);
                }
            }
        }
        item.put("line_min", lineMin);
        item.put("line_max", lineMax);
        item.put("line_count", lineCount);
    }
}
