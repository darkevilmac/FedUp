package com.tridevmc.fedup.extract.internal.apk;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.tridevmc.fedup.extract.internal.gql.RedditGQLOperation;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.core.dex.attributes.AType;
import jadx.core.dex.attributes.AttrNode;
import jadx.core.dex.attributes.AttributeStorage;
import jadx.core.dex.attributes.FieldInitInsnAttr;
import jadx.core.dex.instructions.ConstStringNode;
import jadx.core.dex.nodes.FieldNode;
import org.tinylog.Logger;
import org.tinylog.TaggedLogger;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class APKAnalysisStepGQLOperations implements IAPKAnalysisStep<List<RedditGQLOperation>> {

    private static final Field ATTR_NODE_STORAGE;

    private static final TaggedLogger LOG = Logger.tag(APKAnalyzer.class.getCanonicalName());

    static {
        try {
            ATTR_NODE_STORAGE = AttrNode.class.getDeclaredField("storage");
            ATTR_NODE_STORAGE.setAccessible(true);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public List<RedditGQLOperation> perform(JadxDecompiler jadx) {
        return findGQLOperations(jadx);
    }

    private List<RedditGQLOperation> findGQLOperations(JadxDecompiler jadx) {
        // Find all classes with 3 final fields and a constructor that takes 3 strings.
        Predicate<JavaClass> operationClassPredicate = javaClass -> {
            var fields = javaClass.getFields();
            if (fields.size() != 3) {
                return false;
            }
            for (var field : fields) {
                if (!field.getAccessFlags().isFinal()
                        || !field.getType().isObject()
                        || !field.getType().getObject().equals("java.lang.String")) {
                    return false;
                }
            }
            return javaClass.getMethods().stream().anyMatch(
                    m -> {
                        if (!m.getAccessFlags().isConstructor()) {
                            return false;
                        }
                        var args = m.getArguments();
                        if (args.size() != 3) {
                            return false;
                        }
                        for (var arg : args) {
                            if (!arg.isObject() || !arg.getObject().equals("java.lang.String")) {
                                return false;
                            }
                        }
                        return true;
                    }
            );
        };
        List<JavaClass> classesWithInners = jadx.getClassesWithInners();
        List<JavaClass> potentialRedditGQLOperationClasses = classesWithInners.stream().filter(
                operationClassPredicate
        ).toList();

        // Find all instances where the constructor of the previous classes are called, then store the values of all the strings passed to the constructor.
        List<PotentialRedditGQLOperationClass> potentialOperations = potentialRedditGQLOperationClasses.stream().map(
                clazz -> new PotentialRedditGQLOperationClass(clazz, clazz.getMethods().stream().filter(
                        m -> m.getAccessFlags().isConstructor()
                ).flatMap(constructor -> getArgumentSetsForConstructor(constructor).stream().filter(Objects::nonNull)).toList())
        ).filter(PotentialRedditGQLOperationClass::hasAnyArgumentSets).toList();

        return potentialOperations.stream().flatMap(
                p -> p.argumentSets.stream().map(
                        a -> new RedditGQLOperation(
                                a.arg0,
                                a.arg1,
                                a.arg2
                        )
                )
        ).toList();
    }

    private List<ArgumentSet> getArgumentSetsForConstructor(JavaMethod constructor) {

        var stringArguments = constructor.getArguments().stream().filter(
                a -> a.isObject() && a.getObject().equals("java.lang.String")
        ).toList();
        if (constructor.getArguments().size() == 3 && stringArguments.size() == 3) {
            return getArgumentSetsForDataClassStyleConstructor(constructor);
        } else if (constructor.getArguments().size() == 0) {
            return Lists.newArrayList(getArgumentSetsForNoArgConstructor(constructor));
        } else if (stringArguments.size() >= 3) {
            return getArgumentSetsForStringConstructor(constructor);
        } else {
            LOG.debug("Found unknown constructor: " + constructor.toString());
            return ImmutableList.of();
        }
    }

    /**
     * This is assumed to be a constructor that takes at least three string arguments, so we just want to find the ones that are most likely to be the operation id, name, and definition.
     *
     * @param constructor The constructor to find the argument sets for.
     * @return The list of argument sets found.
     */
    private List<ArgumentSet> getArgumentSetsForStringConstructor(JavaMethod constructor) {
        LOG.debug("Found potential RedditGQLOperation constructor: " + constructor.toString());
        Predicate<String> operationIdPredicate = s -> {
            // An operationId is 12 characters long and contains only numbers and lowercase letters.
            return s.length() == 12 && s.chars().allMatch(
                    c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
            );
        };
        Predicate<String> operationNamePredicate = s -> {
            // An operation name is a string that starts with an uppercase letter and contains only letters and numbers.
            var firstChar = s.charAt(0);
            var isAlphaNumeric = s.chars().allMatch(
                    c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
            );
            return firstChar == Character.toUpperCase(firstChar) && isAlphaNumeric;
        };
        Predicate<String> operationDefinitionPredicate = s -> {
            // An operation definition is a string that contains the word "query" or "mutation".
            var sLower = s.toLowerCase();
            return sLower.contains("query") || sLower.contains("mutation");
        };

        var argCount = constructor.getArguments().size();
        return constructor.getUseIn().stream().flatMap(
                javaNode -> {
                    if (javaNode instanceof JavaMethod && javaNode.getFullName().contains("<clinit>")) {
                        // Static initializer, this is likely a class used to store constants.
                        var declaringClass = javaNode.getDeclaringClass();
                        return declaringClass.getFields().stream().map(
                                field -> {
                                    FieldNode fieldNode = field.getFieldNode();
                                    if (fieldNode.getType().isObject() &&
                                            Objects.equals(fieldNode.getType().getObject(), constructor.getDeclaringClass().getRawName())) {
                                        var attributeStorageFromNode = getAttributeStorageFromNode(fieldNode);
                                        var fieldInitInsnAttr = (FieldInitInsnAttr) attributeStorageFromNode.get(AType.FIELD_INIT_INSN);
                                        if (fieldInitInsnAttr != null) {
                                            var arguments = fieldInitInsnAttr.getInsn().getArguments();
                                            var insnArgs = StreamSupport.stream(arguments.spliterator(), false).toList();
                                            return insnArgs;
                                        }
                                    }
                                    return null;
                                }
                        ).filter(f -> f != null && f.size() == argCount);
                    }
                    return Stream.empty();
                }
        ).map(
                f -> {
                    var stringArgs = f.stream().filter(a -> a.getType().isObject() && a.getType().getObject().equals("java.lang.String")).map(a -> {
                        var s = a.toString();
                        var l = s.length();
                        return s.substring(2, l - 2);
                    }).toList();
                    if (stringArgs.size() >= 3) {
                        var operationId = stringArgs.stream().filter(operationIdPredicate).findFirst().orElse(null);
                        var operationName = stringArgs.stream().filter(operationNamePredicate).findFirst().orElse(null);
                        var operationDefinition = stringArgs.stream().filter(operationDefinitionPredicate).findFirst().orElse(null);
                        if (operationId != null && operationName != null && operationDefinition != null) {
                            return new ArgumentSet(operationId, operationName, operationDefinition);
                        } else {
                            LOG.debug("Unknown constructor: " + constructor);
                        }
                    }
                    return null;
                }
        ).filter(Objects::nonNull).toList();
    }

    /**
     * Gets arguments that are passed to the given data class style constructor.
     * This constructor is assumed to take three String arguments and nothing else.
     * The order is assumed to be operationId, operationName, operationDefinition.
     *
     * @param constructor The constructor to get the arguments for.
     * @return The list of argument sets found.
     */
    private List<ArgumentSet> getArgumentSetsForDataClassStyleConstructor(JavaMethod constructor) {
        LOG.debug("Found data class style constructor: " + constructor);
        // This is assumed to be a constructor that takes three string arguments, so we just want to find the uses and extract the values passed.
        var clazz = constructor.getDeclaringClass();
        return constructor.getUseIn().stream().flatMap(
                javaNode -> {
                    if (constructor.getFullName().contains("firebase")) {
                        LOG.debug("Found use in: " + javaNode);
                    }
                    if (javaNode instanceof JavaMethod && javaNode.getFullName().contains("<clinit>")) {
                        // Static initializer, this is likely a class used to store constants.
                        var declaringClass = javaNode.getDeclaringClass();
                        return declaringClass.getFields().stream().map(
                                field -> {
                                    FieldNode fieldNode = field.getFieldNode();
                                    if (fieldNode.getType().isObject() &&
                                            Objects.equals(fieldNode.getType().getObject(), clazz.getFullName())) {
                                        var attributeStorageFromNode = getAttributeStorageFromNode(fieldNode);
                                        var fieldInitInsnAttr = (FieldInitInsnAttr) attributeStorageFromNode.get(AType.FIELD_INIT_INSN);
                                        if (fieldInitInsnAttr != null) {
                                            var arguments = fieldInitInsnAttr.getInsn().getArguments();
                                            var insnArgs = StreamSupport.stream(arguments.spliterator(), false).toList();
                                            return insnArgs;
                                        }
                                    }
                                    return null;
                                }
                        ).filter(f -> f != null && f.size() == 3);
                    }
                    return Stream.empty();
                }
        ).map(
                f -> {
                    var arg0 = f.get(0).toString();
                    var arg1 = f.get(1).toString();
                    var arg2 = f.get(2).toString();
                    arg0 = arg0.substring(2, arg0.length() - 2);
                    arg1 = arg1.substring(2, arg1.length() - 2);
                    arg2 = arg2.substring(2, arg2.length() - 2);
                    // Remove any \n characters from arg2.
                    arg2 = arg2.replace("\\n", "");
                    return new ArgumentSet(
                            arg0,
                            arg1,
                            arg2
                    );
                }
        ).toList();
    }

    /**
     * Gets the values assigned to the fields of the class by the given default constructor.
     * <p>
     * This seems to be caused by a compiler optimization/obfuscation, or just some weird Kotlin thing.
     *
     * @param constructor The constructor to get the values from.
     * @return The values assigned to the fields of the class by the given default constructor.
     */
    private ArgumentSet getArgumentSetsForNoArgConstructor(JavaMethod constructor) {
        LOG.debug("Found no-arg constructor: " + constructor);
        // This is assumed to be a constructor that takes no arguments, so we need to scan the actual code to find any string literals.
        var methodNode = constructor.getMethodNode();
        methodNode.reload();
        var constStrings = Arrays.stream(methodNode.getInstructions())
                .filter(i -> i instanceof ConstStringNode)
                .map(n -> ((ConstStringNode) n).getString())
                .toList();
        if (methodNode.getInstructions().length == 0) {
            LOG.debug("No instructions for method: " + constructor.getFullName());
            return null;
        }
        if (constStrings.size() == 0) {
            LOG.debug("No const strings for method: " + constructor.getFullName());
            LOG.debug(Arrays.toString(methodNode.getInstructions()));
            return null;
        }
        if (constStrings.size() == 3) {
            var arg0 = constStrings.get(0);
            var arg1 = constStrings.get(1);
            var arg2 = constStrings.get(2);
            return new ArgumentSet(
                    arg0,
                    arg1,
                    arg2
            );
        } else {
            LOG.debug("Unknown constructor: " + constructor.getFullName());
            LOG.debug("Const strings: " + constStrings);
        }
        return null;
    }

    private AttributeStorage getAttributeStorageFromNode(AttrNode node) {
        try {
            AttributeStorage storage = (AttributeStorage) ATTR_NODE_STORAGE.get(node);
            return storage;
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }


    private record ArgumentSet(
            String arg0,
            String arg1,
            String arg2
    ) {

    }

    private static final class PotentialRedditGQLOperationClass {

        private JavaClass clazz;
        private List<ArgumentSet> argumentSets;

        private PotentialRedditGQLOperationClass(
                JavaClass clazz,
                List<ArgumentSet> argumentSets
        ) {
            this.clazz = clazz;
            this.argumentSets = argumentSets;
        }

        private void addArgumentSet(ArgumentSet argumentSet) {
            this.argumentSets.add(argumentSet);
        }

        public boolean hasAnyArgumentSets() {
            return !this.argumentSets.isEmpty();
        }

        @Override
        public String toString() {
            return "PotentialRedditGQLOperationClass{" +
                    "clazz=" + clazz +
                    ", argumentSets=" + argumentSets +
                    '}';
        }

    }

}
