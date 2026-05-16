package com.glaurung.jvmtool;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Modifier;
import com.github.javaparser.ast.NodeList;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.ConstructorDeclaration;
import com.github.javaparser.ast.body.EnumDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.Parameter;
import com.github.javaparser.ast.body.RecordDeclaration;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.type.ReferenceType;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class AstSummary {
    private AstSummary() {}

    static Map<String, Object> fromSource(String source) {
        Map<String, Object> out = new LinkedHashMap<>();
        ParserConfiguration configuration = new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.BLEEDING_EDGE);
        ParseResult<CompilationUnit> parsed = new JavaParser(configuration).parse(source);
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
            out.put("imports", List.of());
            out.put("types", List.of());
            out.put("field_count", 0);
            out.put("constructor_count", 0);
            out.put("method_count", 0);
            return out;
        }
        CompilationUnit unit = parsed.getResult().get();
        out.put("package_name", unit.getPackageDeclaration().map(pd -> pd.getNameAsString()).orElse(null));
        out.put("imports", unit.getImports().stream().map(importDecl -> importDecl.getNameAsString()).toList());
        List<Map<String, Object>> types = new ArrayList<>();
        int fieldCount = 0;
        int constructorCount = 0;
        int methodCount = 0;
        for (TypeDeclaration<?> type : unit.getTypes()) {
            Map<String, Object> typeInfo = new LinkedHashMap<>();
            typeInfo.put("name", type.getNameAsString());
            typeInfo.put("kind", kind(type));
            typeInfo.put("is_public", type.isPublic());
            typeInfo.put("modifiers", modifiers(type.getModifiers()));
            typeInfo.put("annotations", annotations(type.getAnnotations()));
            List<Map<String, Object>> fields = fields(type);
            List<Map<String, Object>> constructors = constructors(type);
            List<Map<String, Object>> methodDetails = methods(type);
            List<String> methods = methodDetails.stream()
                    .map(method -> String.valueOf(method.get("name")))
                    .distinct()
                    .toList();
            typeInfo.put("fields", fields);
            typeInfo.put("constructors", constructors);
            typeInfo.put("methods", methods);
            typeInfo.put("method_details", methodDetails);
            fieldCount += fields.size();
            constructorCount += constructors.size();
            methodCount += methodDetails.size();
            types.add(typeInfo);
        }
        out.put("types", types);
        out.put("type_count", types.size());
        out.put("field_count", fieldCount);
        out.put("constructor_count", constructorCount);
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

    private static List<Map<String, Object>> fields(TypeDeclaration<?> type) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (FieldDeclaration field : type.getFields()) {
            for (VariableDeclarator variable : field.getVariables()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("name", variable.getNameAsString());
                item.put("type", variable.getTypeAsString());
                item.put("modifiers", modifiers(field.getModifiers()));
                item.put("annotations", annotations(field.getAnnotations()));
                out.add(item);
            }
        }
        return out;
    }

    private static List<Map<String, Object>> constructors(TypeDeclaration<?> type) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (ConstructorDeclaration constructor : type.getConstructors()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", constructor.getNameAsString());
            item.put("parameter_count", constructor.getParameters().size());
            item.put("parameters", parameters(constructor.getParameters()));
            item.put("modifiers", modifiers(constructor.getModifiers()));
            item.put("annotations", annotations(constructor.getAnnotations()));
            item.put("thrown_exceptions", thrown(constructor.getThrownExceptions()));
            out.add(item);
        }
        return out;
    }

    private static List<Map<String, Object>> methods(TypeDeclaration<?> type) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (MethodDeclaration method : type.getMethods()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", method.getNameAsString());
            item.put("return_type", method.getTypeAsString());
            item.put("parameter_count", method.getParameters().size());
            item.put("parameters", parameters(method.getParameters()));
            item.put("modifiers", modifiers(method.getModifiers()));
            item.put("annotations", annotations(method.getAnnotations()));
            item.put("thrown_exceptions", thrown(method.getThrownExceptions()));
            out.add(item);
        }
        return out;
    }

    private static List<Map<String, Object>> parameters(NodeList<Parameter> parameters) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Parameter parameter : parameters) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", parameter.getNameAsString());
            item.put("type", parameter.getTypeAsString());
            item.put("is_varargs", parameter.isVarArgs());
            item.put("annotations", annotations(parameter.getAnnotations()));
            out.add(item);
        }
        return out;
    }

    private static List<String> modifiers(NodeList<Modifier> modifiers) {
        return modifiers.stream().map(modifier -> modifier.getKeyword().asString()).toList();
    }

    private static List<String> annotations(NodeList<AnnotationExpr> annotations) {
        return annotations.stream().map(annotation -> annotation.getNameAsString()).toList();
    }

    private static List<String> thrown(NodeList<ReferenceType> thrown) {
        return thrown.stream().map(ReferenceType::asString).toList();
    }
}
