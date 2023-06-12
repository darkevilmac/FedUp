package com.tridevmc.fedup.extract.internal.apk;

import com.google.common.collect.ImmutableList;
import com.tridevmc.fedup.extract.api.apk.IAPKAnalysisResult;
import com.tridevmc.fedup.extract.api.apk.IAPKAnalyzer;
import com.tridevmc.fedup.extract.api.gql.IRedditGQLOperation;
import com.tridevmc.fedup.extract.internal.gql.RedditGQLOperation;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.core.dex.attributes.AType;
import jadx.core.dex.attributes.AttrNode;
import jadx.core.dex.attributes.AttributeStorage;
import jadx.core.dex.attributes.FieldInitInsnAttr;
import jadx.core.dex.nodes.FieldNode;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;


public class APKAnalyzer implements IAPKAnalyzer {

    private final File apkFile;
    private final Field ATTR_NODE_STORAGE;
    private JadxDecompiler jadx;

    {
        try {
            ATTR_NODE_STORAGE = AttrNode.class.getDeclaredField("storage");
            ATTR_NODE_STORAGE.setAccessible(true);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        }
    }

    public APKAnalyzer(File apkFile) {
        this.apkFile = apkFile;
    }

    @Override
    public IAPKAnalysisResult analyzeAPK() {
        var gqlOperations = this.findGQLOperations();
        var rawOAuthTokenId = this.findRawOAuthClientId();
        ImmutableList<IRedditGQLOperation> gqlOperationsImmutable = ImmutableList.copyOf(gqlOperations);
        return new APKAnalysisResult(gqlOperationsImmutable, rawOAuthTokenId);
    }

    private String determineOAuthClientIdKey() {
        // TODO: Actually use JADX to find the authorization header setup code, then work backwards to find the key. Odds are it's always going to be "oauth_client_id" but it's better to be safe than sorry.
        return "oauth_client_id";
    }

    private String findRawOAuthClientId() {
        // Iterate over the entries in the APK file and find any XML files to scan.
        // For each XML file, scan it for the string "oauth_client_id" and extract the value.
        // Return the first value found.
        var jadx = this.getJadxDecompiler();
        var oauthClientIdKey = this.determineOAuthClientIdKey();

        return jadx.getResources().stream().flatMap(p -> p.loadContent().getSubFiles().stream()).filter(p -> p.getName().endsWith(".xml"))
                .flatMap(
                        p -> {
                            try {
                                var s = p.getText().getCodeStr();
                                // Make a temp file to hold the XML data.
                                var tempFile = File.createTempFile("fedup-extract", ".xml");
                                Files.write(tempFile.toPath(), s.getBytes(StandardCharsets.UTF_8));
                                var documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
                                var document = documentBuilder.parse(tempFile);
                                document.normalize();

                                var nodesOut = new ArrayList<OAuthClientIDCandidate>();
                                var nodesToParse = new ArrayList<Node>();
                                nodesToParse.add(document.getDocumentElement());
                                while (!nodesToParse.isEmpty()) {
                                    var node = nodesToParse.remove(0);
                                    if (node.hasChildNodes()) {
                                        for (int i = 0; i < node.getChildNodes().getLength(); i++) {
                                            nodesToParse.add(node.getChildNodes().item(i));
                                        }
                                    }
                                    if (node.hasAttributes()) {
                                        // Scan all the attributes of this node to see if any of them are the OAuth client ID key.
                                        for (int i = 0; i < node.getAttributes().getLength(); i++) {
                                            var attribute = node.getAttributes().item(i);
                                            if (attribute.getNodeName().equals(oauthClientIdKey)) {
                                                // Found the OAuth client ID key, return the value.
                                                nodesOut.add(new OAuthClientIDCandidate(attribute.getNodeName(),
                                                                                        attribute.getNodeValue()));
                                            } else if (attribute.getNodeValue().equals(oauthClientIdKey)) {
                                                if (attribute.getNodeName().equals("name")) {
                                                    // This likely contains the value as raw text in a child node, extract it.
                                                    var childValue = node.getFirstChild().getTextContent();
                                                    nodesOut.add(new OAuthClientIDCandidate(attribute.getNodeValue(),
                                                                                            childValue));
                                                } else {
                                                    // Found the OAuth client ID key, return the value.
                                                    nodesOut.add(new OAuthClientIDCandidate(attribute.getNodeValue(),
                                                                                            attribute.getNodeName()));
                                                }
                                            }
                                        }
                                    }
                                }
                                return nodesOut.stream();
                            } catch (IOException | ParserConfigurationException | SAXException e) {
                                throw new RuntimeException(e);
                            }
                        }
                ).filter(
                        Objects::nonNull
                ).findFirst().map(
                        OAuthClientIDCandidate::value
                ).orElseThrow(
                        () -> new RuntimeException("Failed to find raw OAuth client ID.")
                );
    }

    private record OAuthClientIDCandidate(String name, String value) {

    }

    private List<RedditGQLOperation> findGQLOperations() {
        // First use jadx to decompile the APK file to bytecode.
        // Return the list of operations found.
        var jadx = getJadxDecompiler();

        // Find all classes with 3 final fields and a constructor that takes 3 strings.
        var operationClassPredicate = new Predicate<JavaClass>() {
            @Override
            public boolean test(JavaClass javaClass) {
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
            }
        };
        List<JavaClass> classesWithInners = jadx.getClassesWithInners();
        List<JavaClass> potentialRedditGQLOperationClasses = classesWithInners.stream().filter(
                operationClassPredicate
        ).toList();

        // Find all instances where the constructor of the previous classes are called, then store the values of all the strings passed to the constructor.
        List<PotentialRedditGQLOperationClass> potentialOperations = potentialRedditGQLOperationClasses.stream().map(
                clazz -> {
                    var constructor = clazz.getMethods().stream().filter(
                            m -> m.getAccessFlags().isConstructor()
                    ).findFirst().orElseThrow(
                            () -> new RuntimeException("Failed to find constructor for class " + clazz.getFullName())
                    );
                    var constructorUsedIn = constructor.getUseIn();
                    return new PotentialRedditGQLOperationClass(clazz, constructorUsedIn.stream().flatMap(
                            javaNode -> {
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
                    ).toList());
                }
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

    private AttributeStorage getAttributeStorageFromNode(AttrNode node) {
        try {
            AttributeStorage storage = (AttributeStorage) ATTR_NODE_STORAGE.get(node);
            return storage;
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    private JadxDecompiler getJadxDecompiler() {
        if (this.jadx == null) {
            var jadxArgs = new JadxArgs();
            jadxArgs.setInputFile(
                    this.apkFile
            );
            jadxArgs.setOutDir(
                    new File("jadx-out")
            );
            var jadx = new JadxDecompiler(jadxArgs);
            jadx.load();
            jadx.save();
            this.jadx = jadx;
        }
        return this.jadx;
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
