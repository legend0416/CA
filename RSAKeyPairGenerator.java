/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rsakeypairgenerator;

import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Provider;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.util.Base64;

//add the provider package
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author TAS208
 */
public class RSAKeyPairGenerator {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        KeyPair rsaKey = RSAKeyPairGenerator.genKey(1024);
        RSAKeyPairGenerator.storeKey(rsaKey.getPrivate(), "C:\\Users\\tas208\\Documents\\Practice\\RSAKeyPairGenerator\\keyFile.key");
        //adKey("C:\\Users\\tas208\\Documents\\Practice\\RSAKeyPairGenerator\\keyfile.key");
        
        Key keyLoaded = loadKey("C:\\Users\\tas208\\Documents\\Practice\\RSAKeyPairGenerator\\keyFile.key");
        
    }
        
    public static KeyPair genKey(int keyLength) {
        //add at runtime the Bouncy Castle Provider
    	//the provider is available only for this application
    	Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGtr = null;
        KeyPair rsaKeyPair = null;
        try {
            keyGtr = KeyPairGenerator.getInstance("RSA", Security.getProvider("BC"));
            keyGtr.initialize(keyLength);
            rsaKeyPair = keyGtr.genKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        return rsaKeyPair;
    }
    
    public static void storeKey(Key key, String filePath) {
        
        try(OutputStream fw = new FileOutputStream(filePath)) {
            byte[] encodedStr = Base64.getMimeEncoder().encode(key.getEncoded());
            fw.write(encodedStr);
        } catch(IOException ex) {
            ex.printStackTrace();
        }
    }
     
    public static Key loadKey(String filePath) {
        
        Key key = null;
        try(FileInputStream fis = new FileInputStream(filePath) ) {
            byte[] inputKeyStream = new byte[1024];
            fis.read(inputKeyStream);
            key = new SecretKeySpec(inputKeyStream, "RSA");
            System.out.println(key.getAlgorithm());
            System.out.println(key.getFormat());
            System.out.println(key.getEncoded());
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return key;
        
    }
}
