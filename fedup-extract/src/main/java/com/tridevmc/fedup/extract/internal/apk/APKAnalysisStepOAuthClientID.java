package com.tridevmc.fedup.extract.internal.apk;

import jadx.api.JadxDecompiler;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Objects;

public class APKAnalysisStepOAuthClientID implements IAPKAnalysisStep<String> {

    @Override
    public String perform(JadxDecompiler jadx) {
        return findRawOAuthClientId(jadx);
    }

    private String determineOAuthClientIdKey() {
        // TODO: Actually use JADX to find the authorization header setup code, then work backwards to find the key. Odds are it's always going to be "oauth_client_id" but it's better to be safe than sorry.
        return "oauth_client_id";
    }

    private String findRawOAuthClientId(JadxDecompiler jadx) {
        // Iterate over the entries in the APK file and find any XML files to scan.
        // For each XML file, scan it for the string "oauth_client_id" and extract the value.
        // Return the first value found.
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

}
