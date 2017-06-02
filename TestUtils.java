package utils;

import com.mastercard.api.common.Environment;
import com.mastercard.api.common.apiexception.MCApiRuntimeException;

import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.Properties;

public class TestUtils {

    Properties properties = new Properties();
    Environment environment;

    public TestUtils(Environment environment){
        try {
            //properties.load(TestUtils.class.getClassLoader().getResourceAsStream("openAPI.properties"));
            properties.put("sandbox.privateKeyFile", "/Users/tapasdas/Downloads/MCOpenAPI.p12");
            properties.put("sandbox.privateKeyPassword","tapas123");
            properties.put("sandbox.consumerKey","Px-umVffo5mGfH4_nOx3xxzdLROngtdnO1ur5qSM23ec00a2!562b64342b6363375376726a334757384b734a7833413d3d");
            this.environment = environment;
        } catch (Exception ex){
            ex.printStackTrace();
        }
    }
    
     public PrivateKey getPrivateKey() {
        String fileName = getPrivateKeyFilename();
        String password = getPrivateKeyPassword();
        System.out.println("filename:"+fileName+" password:"+password);
        KeyStore ks;
        Key key;
        try {
            ks = KeyStore.getInstance("PKCS12");
            // get user password and file input stream
            ClassLoader cl = this.getClass().getClassLoader();
            InputStream stream = cl.getResourceAsStream(fileName);
            //
            InputStream is = new FileInputStream("/Users/tapasdas/Downloads/MCOpenAPI.p12");
            //
            ks.load(is, password.toCharArray());

            	
            Enumeration<String> enumeration = ks.aliases ();
            System.out.println("ks "+ks.size());
            //
           // while (enumeration.hasMoreElements()) {
			//	System.out.println("Inside While"+ (String) enumeration.nextElement());
				
			//}
            //
            
            

            // uses the default alias
            String keyAlias = (String) enumeration.nextElement();

            key = ks.getKey(keyAlias, password.toCharArray());
            
        } catch (Exception e) {
            throw new MCApiRuntimeException(e);
        }

        return (PrivateKey) key;
    }

    public String getPrivateKeyFilename(){
        if (this.environment == Environment.PRODUCTION){
            return properties.getProperty("production.privateKeyFile");
        } else {
            return properties.getProperty("sandbox.privateKeyFile");
        }
    }

    public String getPrivateKeyPassword(){
        if (this.environment == Environment.PRODUCTION){
            return properties.getProperty("production.privateKeyPassword");
        } else {
            return properties.getProperty("sandbox.privateKeyPassword");
        }
    }

    public String getConsumerKey(){
        if (this.environment == Environment.PRODUCTION){
            return properties.getProperty("production.consumerKey");
        } else {
            return properties.getProperty("sandbox.consumerKey");
        }
    }

    public boolean validateXML(Object xmlClass, String schemaName){
        final String XML_SCHEMA = schemaName;
        final String W3C_XML_SCHEMA_NS_URI = "http://www.w3.org/2001/XMLSchema";

        SchemaFactory schemaFactory = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI);
        ClassLoader cl = this.getClass().getClassLoader();
        Schema schema;

        try {
            schema = schemaFactory.newSchema(new StreamSource(cl.getResourceAsStream(XML_SCHEMA)));
        } catch (SAXException e){
            return false;
        }

        String xml = "";
        Validator validator = schema.newValidator();

        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(xmlClass.getClass());
            StringWriter st = new StringWriter();
            jaxbContext.createMarshaller().marshal(xmlClass,st);
            xml = st.toString();
        } catch (JAXBException e){
            return false;
        }

        try {
            validator.validate(new StreamSource(new StringReader(xml)));
        } catch (SAXException e) {
            return false;
        } catch (IOException e){
            return false;
        }

        return true;
    }
}
