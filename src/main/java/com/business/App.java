package com.business;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
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
import org.w3c.dom.NodeList;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class App {

    public static void main(String[] args) {
        log.info("Hello World!");
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
    private static final String fileName1 = "20515659324-RC-20250204-10.xml"; // for testing purposes of the class
                                                                              // XMLSignatureValidator

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
                    locationSignedDocuments + fileName1);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static void saveXml(Document doc, String outputPath) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "no");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(new File(outputPath));
        transformer.transform(source, result);
    }

    private static final String EXT_NS = "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2";

    public static void injectSignature(Document doc, PrivateKey privateKey, X509Certificate certificate)
            throws Exception {

        // Locate the ExtensionContent element where the signature should be placed
        NodeList extensionContentList = doc.getElementsByTagNameNS(
                "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2", "ExtensionContent");
        Element nodeSign = null;
        for (int i = 0; i < extensionContentList.getLength(); i++) {
            Element element = (Element) extensionContentList.item(i);
            if (element.getTextContent().trim().isEmpty()) {
                nodeSign = element;
                break;
            }
        }

        if (nodeSign == null) {
            nodeSign = doc.getDocumentElement();
        }

        // Create XMLSignature object
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        List<Transform> transforms = Arrays.asList(
                fac.newTransform(Transform.ENVELOPED,
                        (TransformParameterSpec) null));

        // Build Reference
        Reference ref = fac.newReference(
                "",
                fac.newDigestMethod(DigestMethod.SHA1, null),
                transforms,
                null,
                null);

        // Create SignedInfo with inclusive canonicalization
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(
                        CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                Collections.singletonList(ref));

        // Build KeyInfo
        KeyInfoFactory kif = KeyInfoFactory.getInstance();
        X509Data xd = kif.newX509Data(Collections.singletonList(certificate));
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        // Configure context *before* signing
        DOMSignContext dsc = new DOMSignContext(privateKey, nodeSign);
        dsc.setDefaultNamespacePrefix("ds");

        // Generate & sign
        XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(dsc);

        NodeList signatureList = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
                "Signature");

        if (signatureList.getLength() > 0) {
            Element signatureElement = (Element) signatureList.item(0);
            if (!signatureElement.hasAttribute("Id")) {
                signatureElement.setAttribute("Id", "signatureFACTURALOPERU");
                signatureElement.setIdAttribute("Id", true);
            }
        }

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
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setNamespaceAware(true);
            // factory.setValidating(true);
            factory.setValidating(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            return builder.parse(new File(
                    locationUnsignedDocuments + sDocument));
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

}
