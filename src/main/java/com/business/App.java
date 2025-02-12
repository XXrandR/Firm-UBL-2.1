package com.business;

import org.apache.xml.security.c14n.Canonicalizer;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import lombok.extern.slf4j.Slf4j;
import com.business.XMLSignatureValidator;

@Slf4j
public class App {
    public static void main(String[] args) {
        System.out.println("Hello World!");
		XmlSec xmlSec = new XmlSec();
		xmlSec.generateDocument();
    }
}

@Slf4j
class XmlSec {

    private final String locationUnsignedDocuments;
    private final String locationSignedDocuments;
    private final String certificatePath;
	private static final String fileName = "20515659324-RC-20250204-10.xml";

    public XmlSec() {
		locationUnsignedDocuments = "/home/maximus/jhosua/JHOSUA/tests/testfirm/unsigned/";
		locationSignedDocuments = "/home/maximus/jhosua/JHOSUA/tests/testfirm/signed/";
		certificatePath = "certificate.pem";
    }

    public void generateDocument() {
        try {
            log.info("Opening document..");
            Document doc = openDocument(fileName);

            log.info("Loading keys and certs..");
            Object[] keyCert = loadKeyAndCert(certificatePath);
            PrivateKey privateKey = (PrivateKey) keyCert[0];
            X509Certificate certificate = (X509Certificate) keyCert[1];

            log.info("Injecting Signatures..");
            injectSignature(doc, privateKey, certificate);

            log.info("Saving Document..");
            saveXml(doc, locationSignedDocuments + fileName);

            log.info("Validating Firm...");
            XMLSignatureValidator.validateXMLSignature(
                    locationSignedDocuments + fileName);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static void saveXml(Document doc, String outputPath) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(outputPath));
        transformer.transform(source, result);
    }

    private static byte[] customCanonicalize(Node node) throws Exception {
		Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            canon.canonicalizeSubtree(node, outputStream);
            return outputStream.toByteArray();
        }
    }

    // Example implementation for inclusive canonicalization
    private static String inclusiveCanonicalize(Node node) throws Exception {
        Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            canon.canonicalizeSubtree(node, outputStream);
            return outputStream.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static void injectSignature(Document doc, PrivateKey privateKey, X509Certificate certificate)
            throws Exception {

        //log.info("Original unsigned XML:\n{}", documentToString(doc));
        // Namespace URIs
        String extNs = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";
        String dsNs = "http://www.w3.org/2000/09/xmldsig#";

        // Create the <ext:UBLExtensions> structure
        Element ublExtensions;
        // Element ublExtensions = doc.createElementNS(extNs, "ext:UBLExtensions");
        // NodeList ublExtensionsList = doc.getElementsByTagName("UBLExtensions");
        List<String> allElementNames = getAllElementNames(doc);
        NodeList ublExtensionsList = doc.getElementsByTagNameNS(extNs, "UBLExtensions");
        log.info("All element names in the document: " + allElementNames);
        if (ublExtensionsList.getLength() > 0) {
            ublExtensions = (Element) ublExtensionsList.item(0);
        } else {
            ublExtensions = doc.createElementNS(extNs, "ext:UBLExtensions");
            Element root = doc.getDocumentElement();
            root.insertBefore(ublExtensions, root.getFirstChild());
        }

        NodeList ublExtensionList = doc.getElementsByTagNameNS(extNs, "UBLExtension");
        Element ublExtension;
        log.info("All element names in the document: " + allElementNames);
        if (ublExtensionList.getLength() > 0) {
            ublExtension = (Element) ublExtensionList.item(0);
        } else {
            ublExtension = doc.createElementNS(extNs, "ext:UBLExtension");
            Element root = doc.getDocumentElement();
            root.insertBefore(ublExtension, root.getFirstChild());
        }

        NodeList extensionContentList = doc.getElementsByTagNameNS(extNs, "ExtensionContent");
        Element extensionContent;
        log.info("All element names in the document: " + allElementNames);
        if (extensionContentList.getLength() > 0) {
            extensionContent = (Element) extensionContentList.item(0);
        } else {
            extensionContent = doc.createElementNS(extNs, "ext:UBLExtension");
            Element root = doc.getDocumentElement();
            root.insertBefore(ublExtension, root.getFirstChild());
        }

        // Element extensionContent = doc.createElementNS(extNs,
        // "ext:ExtensionContent");
        Element signature = doc.createElementNS(dsNs, "ds:Signature");
        signature.setAttribute("Id", "signatureFACTURALOPERU");

        // Build <ds:SignedInfo>
        Element signedInfo = doc.createElementNS(dsNs, "ds:SignedInfo");
        Element canonicalizationMethod = createElementWithAttribute(doc, dsNs, "ds:CanonicalizationMethod", "Algorithm",
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"); // Inclusive for SignedInfo
        Element signatureMethod = createElementWithAttribute(doc, dsNs, "ds:SignatureMethod", "Algorithm",
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1");

        // Build <ds:Reference>
        Element reference = doc.createElementNS(dsNs, "ds:Reference");
        reference.setAttribute("URI", "");
        Element transforms = doc.createElementNS(dsNs, "ds:Transforms");

        // Add enveloped-signature transform
        Element transformEnveloped = createElementWithAttribute(doc, dsNs, "ds:Transform", "Algorithm",
                "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        transforms.appendChild(transformEnveloped);

        Element digestMethod = createElementWithAttribute(doc, dsNs, "ds:DigestMethod", "Algorithm",
                "http://www.w3.org/2000/09/xmldsig#sha1");
        Element digestValue = doc.createElementNS(dsNs, "ds:DigestValue");

        // Compute digest with EXCLUSIVE canonicalization (as per transforms)
        String canonicalXml = inclusiveCanonicalize(doc.getDocumentElement()); // Use exclusive C14N here
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digestBytes = md.digest(canonicalXml.getBytes(StandardCharsets.UTF_8));
        digestValue.setTextContent(Base64.getEncoder().encodeToString(digestBytes));

        // Assemble <ds:Reference>
        reference.appendChild(transforms);
        reference.appendChild(digestMethod);
        reference.appendChild(digestValue);

        // Assemble <ds:SignedInfo>
        signedInfo.appendChild(canonicalizationMethod);
        signedInfo.appendChild(signatureMethod);
        signedInfo.appendChild(reference);

        // Compute signature over SignedInfo with INCLUSIVE canonicalization (as per
        // CanonicalizationMethod)
        byte[] signedInfoCanonicalized = customCanonicalize(signedInfo); // Use inclusive C14N here
		String canonicalizedBase64 = Base64.getEncoder().encodeToString(signedInfoCanonicalized);
		log.info("Canonicalized <SignedInfo> (Base64): {}", canonicalizedBase64);
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(privateKey);
        sig.update(signedInfoCanonicalized);
        byte[] signatureBytes = sig.sign();
        Element signatureValue = doc.createElementNS(dsNs, "ds:SignatureValue");
        signatureValue.setTextContent(Base64.getEncoder().encodeToString(signatureBytes));
        log.debug("Computed SignatureValue (SHA1-RSA): {}", signatureValue.getTextContent());

        // Build <ds:KeyInfo>
        Element keyInfo = doc.createElementNS(dsNs, "ds:KeyInfo");
        Element x509Data = doc.createElementNS(dsNs, "ds:X509Data");
        Element x509Certificate = doc.createElementNS(dsNs, "ds:X509Certificate");
        x509Certificate.setTextContent(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        log.debug("Added X509 Certificate (Issuer DN): {}", certificate.getIssuerX500Principal().getName());
        x509Data.appendChild(x509Certificate);
        keyInfo.appendChild(x509Data);

        // Assemble the <ds:Signature>
        signature.appendChild(signedInfo);
        signature.appendChild(signatureValue);
        signature.appendChild(keyInfo);

        // Build the full structure and inject
        extensionContent.appendChild(signature);
        ublExtension.appendChild(extensionContent);
        ublExtensions.appendChild(ublExtension);
        Element root = doc.getDocumentElement();
        root.insertBefore(ublExtensions, root.getFirstChild());
        //log.info("Signed XML:\n{}", documentToString(doc));

    }

    private static String canonicalizeSignedInfo(Element signedInfo) throws Exception {
        Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            // Canonicalize the <ds:SignedInfo> subtree and write to the stream
            canon.canonicalizeSubtree(signedInfo, outputStream);
            // Convert the bytes to a UTF-8 string
            return outputStream.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static String canonicalize(Node node) throws Exception {
        Canonicalizer canon = Canonicalizer.getInstance(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            canon.canonicalizeSubtree(node, outputStream);
            return outputStream.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static Element createElementWithAttribute(Document doc, String ns, String tag, String attrName,
            String attrValue) {
        Element element = doc.createElementNS(ns, tag);
        element.setAttribute(attrName, attrValue);
        return element;
    }

    private static Object[] loadKeyAndCert(String certificatePath) throws Exception {
        org.apache.xml.security.Init.init();
        ClassLoader classLoader = XmlSec.class.getClassLoader();
        try (InputStream inputStream = classLoader.getResourceAsStream(certificatePath);
                PEMParser pemParser = new PEMParser(new InputStreamReader(inputStream))) {

            PrivateKey privateKey = null;
            X509Certificate certificate = null;
            Object pemObject;

            while ((pemObject = pemParser.readObject()) != null) {
                if (pemObject instanceof X509CertificateHolder certHolder) {
                    certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
                } else if (pemObject instanceof PEMKeyPair keyPair) {
                    privateKey = new JcaPEMKeyConverter().getPrivateKey(keyPair.getPrivateKeyInfo());
                } else if (pemObject instanceof PrivateKeyInfo privateKeyInfo) {
                    privateKey = new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
                }
            }

            if (privateKey == null || certificate == null) {
                throw new RuntimeException("Missing key/cert in PEM file");
            }

            return new Object[] { privateKey, certificate };
        }
    }

    // into a DOM element
    private Document openDocument(String sDocument) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setIgnoringElementContentWhitespace(true);
            factory.setNamespaceAware(true);
            factory.setValidating(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(new File(
                    locationUnsignedDocuments + sDocument));
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    /* HELPERS FOR LOGGING */
    private static String documentToString(Document doc) {
        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            return writer.toString();
        } catch (TransformerException e) {
            throw new RuntimeException("Failed serializing Document", e);
        }
    }

    public static List<String> getAllElementNames(Document doc) {
        Set<String> elementNames = new HashSet<>();
        traverseDOM(doc.getDocumentElement(), elementNames);
        return new ArrayList<>(elementNames);
    }

    private static void traverseDOM(Node node, Set<String> elementNames) {
        if (node.getNodeType() == Node.ELEMENT_NODE) {
            Element element = (Element) node;
            String tagName = element.getTagName();
            elementNames.add(tagName);
        }

        NodeList children = node.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            traverseDOM(children.item(i), elementNames);
        }
    }

}
