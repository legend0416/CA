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
    public static void main(String[] args) throws IOException {
        // TODO code application logic here
        KeyPair rsaKey = RSAKeyPairGenerator.genKey(1024);
        /**
        if(rsaKey != null) {
            System.out.println("haha");
        }
        else {
            System.out.println("TT");
        }        System.out.println(rsaKey.getPrivate());
        **/
        //System.out.println(rsaKey.getPublic());
        RSAKeyPairGenerator.storeKey(rsaKey.getPrivate(), "C:\\Users\\tas208\\Documents\\Practice\\RSAKeyPairGenerator\\");
        //adKey("C:\\Users\\tas208\\Documents\\Practice\\RSAKeyPairGenerator\\keyfile.key");
        
        Key keyLoaded = loadKey("C:\\Users\\tas208\\Documents\\Practice\\RSAKeyPairGenerator\\keyfile.key");
        
    }
        
    public static KeyPair genKey(int keyLength) {
        //add at runtime the Bouncy Castle Provider
    	//the provider is available only for this application
    	Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keygtr = null;
        try {
            keygtr = KeyPairGenerator.getInstance("RSA", Security.getProvider("BC"));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSAKeyPairGenerator.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        keygtr.initialize(keyLength);
        KeyPair rsaKeyPair = keygtr.genKeyPair();
        return rsaKeyPair;
    }
    
    public static void storeKey(Key key, String filePath) throws IOException {
        System.out.println("storeKey: "+key.getAlgorithm());
        System.out.println("storeKey: "+key.getFormat());
        System.out.println("storeKey: "+key.getEncoded());
        String fileName;
        fileName = new String("keyfile.key");
        OutputStream fw;
        fw = new FileOutputStream(filePath + fileName);
        fw.write(key.getEncoded());
        fw.flush();
        fw.close();
    }
     
    public static Key loadKey(String filePath) throws FileNotFoundException, IOException {
        InputStream fi;
        fi = new FileInputStream(filePath);
        byte[] inputKeyStream = new byte[1024];
        fi.read(inputKeyStream);
        System.out.println(fi);
        Key key;
        key = new SecretKeySpec(inputKeyStream, "RSA");
        System.out.println(key.getAlgorithm());
        System.out.println(key.getFormat());
        System.out.println(key.getEncoded());
        return key;
        
    }
}
