/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package csrpractice;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

/**
 *
 * @author TAS208
 */
public class CSRPractice {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        CSRPractice csrp = new CSRPractice();
        
    }
    
    PKCS10CertificationRequest genCSR(KeyPair kp, X500Name subject) {
        PKCS10CertificationRequestBuilder csrBuilder =  new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());
        JcaContentSignerBuilder cs = new JcaContentSignerBuilder("SHA256withRSA");
        PKCS10CertificationRequest csr = null;
        try {
            csr = csrBuilder.build(cs.build(kp.getPrivate()));
        } catch (OperatorCreationException ex) {
            ex.printStackTrace();
        }
        
        return csr;
    }
    void storeCSR(PKCS10CertificationRequest csr, String filePath) {
        try(JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(filePath))){
            pw.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
        } catch(Exception ex) {
            ex.printStackTrace();
        }
    }
    PKCS10CertificationRequest loadCSR(String filePath) {
        try(FileInputStream fis = new FileInputStream(filePath)) {
            byte[] is = new byte[1024];
            fis.read(is);
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(is);
        } catch(Exception ex) {
            ex.printStackTrace();
        }
    }
    String getCN(PKCS10CertificationRequest csr) {
    }
    PublicKey getPublicKey(PKCS10CertificationRequest csr) {
        JcaPKCS10CertificationRequest jcacsr = new JcaPKCS10CertificationRequest(csr);
        PublicKey pk = null;
        try {
            pk = jcacsr.getPublicKey();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return pk;
    }

}
