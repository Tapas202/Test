package com.hce.upi.utils;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringWriter;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.transform.OutputKeys;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import java.io.StringReader;

public class ProcessXML {
	
	public static String ApplySignature(String str){
        try{
            //Step 1 : Load the PrivateKey from .p12 file
            File signerFile = new File("/Users/tapasdas/Desktop/DailyStatus/Verify/hce.p12");  // load our privateKey .p12 from config file
			FileInputStream is = new FileInputStream(signerFile);
			KeyStore keystore = KeyStore.getInstance("PKCS12");

			/* Information for certificate to be generated */
			String password = "hceswim1";
			String alias = "1";

			/* getting the key */
			keystore.load(((InputStream) is), password.toCharArray());
			PrivateKey key = (PrivateKey) keystore.getKey(alias, password.toCharArray());

			//Load the Request String into Doc
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			 InputSource ins = new InputSource();
		     ins.setCharacterStream(new StringReader(str));
			Document doc = dbf.newDocumentBuilder().parse(ins);
			
			
	        
	        //Now apply signature
	        XMLSignatureFactory xmlSigFactory = XMLSignatureFactory.getInstance("DOM");
			DOMSignContext domSignCtx = new DOMSignContext(key, doc.getDocumentElement());
			
			Reference ref = null;
			SignedInfo signedInfo = null;
			
			ref = xmlSigFactory.newReference("", xmlSigFactory.newDigestMethod(DigestMethod.SHA256, null),
					Collections.singletonList(
							xmlSigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
					null, null);

			System.out.println("xmlSigFactory.getProvider():" + xmlSigFactory.getProvider());
			signedInfo = xmlSigFactory.newSignedInfo(xmlSigFactory.newCanonicalizationMethod(
					CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null), xmlSigFactory.newSignatureMethod
					("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", (SignatureMethodParameterSpec) null),
					Collections.singletonList(ref));
			
			KeyInfo keyInfo = null;
			KeyValue keyValue = null;
			KeyInfoFactory keyInfoFact = xmlSigFactory.getKeyInfoFactory();
			java.security.cert.Certificate cert = getCertificate("/Users/tapasdas/Desktop/DailyStatus/Verify/Indore_2048_Cert.pem"); //load our Certificate from config
			PublicKey publicKey = cert.getPublicKey();
			try {
				keyValue = keyInfoFact.newKeyValue(publicKey);
			} catch (KeyException ex) {
				ex.printStackTrace();
			}
			keyInfo = keyInfoFact.newKeyInfo(Collections.singletonList(keyValue));
			// Create a new XML Signature

			XMLSignature xmlSignature = xmlSigFactory.newXMLSignature(signedInfo, keyInfo);
			
			xmlSignature.sign(domSignCtx);
	        String output = "";
	        DOMSource domSource = new DOMSource(doc);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.transform(domSource, result);
            writer.flush();
            output = writer.toString();
	        System.out.println("output"+result.getWriter().toString());
	        
	        return result.getWriter().toString();
        }catch(Exception c){
        	c.printStackTrace();
            return "ERROR";
        }
    }
	
	private static Certificate getCertificate(String file) throws CertificateException, FileNotFoundException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		InputStream is = new FileInputStream(new File(file));
		InputStream caInput = new BufferedInputStream(is);
		Certificate ca;
		try {
			ca = cf.generateCertificate(caInput);
			return ca;
		} finally {
			try {
				caInput.close();
			} catch (IOException e) {
			}
			try {
				is.close();
			} catch (IOException e) {
			}
		}
	}
	
	//main method for applying signature on the XML
	public static void main(String[] args) {   
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		try{
			FileInputStream fis = new FileInputStream(new File("/Users/tapasdas/Downloads/ReqPay.xml"));
			
			int nRead;
			byte[] data = new byte[16384];
			while ((nRead = fis.read(data, 0, data.length)) != -1) {
			  buffer.write(data, 0, nRead);
			}
			fis.close();
			buffer.flush();
		}catch(Exception c){
			System.out.println("EXCEPTION "+c.getMessage());
		}
		
		String outputXML = ProcessXML.ApplySignature(new String(buffer.toByteArray()));
		if(!outputXML.equalsIgnoreCase("ERROR")){
			//proceed to send httpsrequest with this string
			
			System.out.println("Verify "+VerifySignature(outputXML));
			System.out.println();
			System.out.println("RAW XML\n"+getRawXML(outputXML));
			
		}
	}
	
	public static String getRawXML(String xml){
		try{
			Document doc = null;
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
	        InputSource ins = new InputSource();
	        ins.setCharacterStream(new StringReader(xml));
	        doc = db.parse(ins);
	        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
	        for (int i = 0; i < nl.getLength(); i++) {
	        	Node node =nl.item(i);
	        	node.getParentNode().removeChild(node);
			}
	        DOMSource domSource = new DOMSource(doc);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.transform(domSource, result);
            writer.flush();
            System.out.println();System.out.println();System.out.println();
            System.out.println("RAW XML"+result.getWriter().toString());
            return result.getWriter().toString();
			
		}catch(Exception c){
			c.printStackTrace();
			return "ERROR";
		}
		
	}
	
	public static boolean VerifySignature(String str){
		try{
			Document doc = null;
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
		DocumentBuilder db = dbf.newDocumentBuilder();
        InputSource ins = new InputSource();
        ins.setCharacterStream(new StringReader(str));
        doc = db.parse(ins);
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0) {
			throw new Exception("No XML Digital Signature Found, document is discarded");
		}
        System.out.println("node value"+nl.item(0).getNodeName());
        
        //Load NPCI Certificate to get the public key from that
        java.security.cert.Certificate cert = getCertificate("/Users/tapasdas/Desktop/DailyStatus/Verify/Indore_2048_Cert.pem"); //load NPCI Certificate 
		PublicKey publicKey = cert.getPublicKey();
        DOMValidateContext valContext = new DOMValidateContext(publicKey, nl.item(0));
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		XMLSignature signature = fac.unmarshalXMLSignature(valContext);
		return signature.validate(valContext);
		}catch(Exception c){
			c.printStackTrace();
			System.out.println("Error"+c.getMessage());
			return false;
		}
	}
	
	
}
