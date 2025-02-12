package com.business;

import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.XMLCryptoContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class XMLSignatureValidator{

    public static boolean validateXMLSignature(String xmlFilePath) {

        try {
            // Load the XML document
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new FileInputStream(xmlFilePath));

            // Find the <ds:Signature> element
            NodeList signatureNodes = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (signatureNodes.getLength() == 0) {
                throw new RuntimeException("No <ds:Signature> element found in the XML.");
            }

            // Get the <ds:Signature> element
            Element signatureElement = (Element) signatureNodes.item(0);

            // Create a DOMValidateContext for validation
            DOMValidateContext validateContext = new DOMValidateContext(new X509KeySelector(), signatureElement);
			validateContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.FALSE);

            // Unmarshal the XMLSignature
            XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
            XMLSignature signature = signatureFactory.unmarshalXMLSignature(validateContext);

            // Validate the signature
            boolean isValid = signature.validate(validateContext);

            if (isValid) {
                log.info("The XML signature is valid.");
            } else {
                log.info("The XML signature is NOT valid.");
                // Check the validation status of each reference
                boolean sv = signature.getSignatureValue().validate(validateContext);
                log.info("Signature validation status: " + sv);

                // Check reference validation status
                for (Object ref : signature.getSignedInfo().getReferences()) {
                    boolean refValid = ((javax.xml.crypto.dsig.Reference) ref).validate(validateContext);
                    log.info("Reference validation status: " + refValid);
                }
            }

            return isValid;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

    }

}

class X509KeySelector extends javax.xml.crypto.KeySelector {
    public javax.xml.crypto.KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method,
            XMLCryptoContext context) throws javax.xml.crypto.KeySelectorException {
        if (keyInfo == null) {
            throw new javax.xml.crypto.KeySelectorException("No <ds:KeyInfo> element found.");
        }
        for (Object keyInfoContent : keyInfo.getContent()) {
            if (keyInfoContent instanceof X509Data) {
                X509Data x509Data = (X509Data) keyInfoContent;
                for (Object data : x509Data.getContent()) {
                    if (data instanceof X509Certificate) {
                        X509Certificate cert = (X509Certificate) data;
                        PublicKey publicKey = cert.getPublicKey();
                        return new SimpleKeySelectorResult(publicKey);
                    }
                }
            }
        }
        throw new javax.xml.crypto.KeySelectorException("No X509Certificate found in <ds:KeyInfo>.");
    }

    private static class SimpleKeySelectorResult implements javax.xml.crypto.KeySelectorResult {
        private final PublicKey publicKey;

        SimpleKeySelectorResult(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        public PublicKey getKey() {
            return publicKey;
        }
    }
}

