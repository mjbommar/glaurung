package com.glaurung.jvmtool;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class AstSummary {
    private AstSummary() {}

    static Map<String, Object> fromSource(String source) {
        Map<String, Object> out = new LinkedHashMap<>();
        ParseResult<CompilationUnit> parsed = new JavaParser().parse(source);
        out.put("parse_success", parsed.isSuccessful());
        out.put("problem_count", parsed.getProblems().size());
        out.put(
                "problems",
                parsed.getProblems().stream()
                        .map(problem -> problem.getMessage())
                        .limit(16)
                        .toList());
        if (parsed.getResult().isEmpty()) {
            out.put("package_name", null);
            out.put("types", List.of());
            out.put("method_count", 0);
            return out;
        }
        CompilationUnit unit = parsed.getResult().get();
        out.put("package_name", unit.getPackageDeclaration().map(pd -> pd.getNameAsString()).orElse(null));
        List<Map<String, Object>> types = new ArrayList<>();
        int methodCount = 0;
        for (TypeDeclaration<?> type : unit.getTypes()) {
            Map<String, Object> typeInfo = new LinkedHashMap<>();
            typeInfo.put("name", type.getNameAsString());
            typeInfo.put("kind", kind(type));
            typeInfo.put("is_public", type.isPublic());
            List<String> methods = type.findAll(MethodDeclaration.class).stream()
                    .map(MethodDeclaration::getNameAsString)
                    .distinct()
                    .toList();
            typeInfo.put("methods", methods);
            methodCount += methods.size();
            types.add(typeInfo);
        }
        out.put("types", types);
        out.put("type_count", types.size());
        out.put("method_count", methodCount);
        return out;
    }

    private static String kind(TypeDeclaration<?> type) {
        if (type instanceof ClassOrInterfaceDeclaration classOrInterface) {
            return classOrInterface.isInterface() ? "interface" : "class";
        }
        if (type instanceof EnumDeclaration) {
            return "enum";
        }
        if (type instanceof RecordDeclaration) {
            return "record";
        }
        return type.getClass().getSimpleName();
    }
}
