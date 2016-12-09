/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crlpractice;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 *
 * @author TAS208
 */
public class CRLPractice {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        CRLPractice crlp = new CRLPractice();
        X509CRL crl = crlp.loadCrl("C:\\Users\\tas208\\Documents\\Practice\\CRLPractice\\src\\resources\\Securessl_revoke_sha2_2014.crl");
        crlp.parseCrl(crl);
        crlp.storeCrl(crl, "C:\\Users\\tas208\\Documents\\Practice\\CRLPractice\\haha.crl");
    }
    void parseCrl(X509CRL crl) {
        System.out.println(crl.getSigAlgName());
    }
    void storeCrl(X509CRL crl, String filePath) {
        try(OutputStream fw = new FileOutputStream(filePath)) {
            byte[] encodedStr = Base64.getMimeEncoder().encode(crl.getEncoded());
            fw.write(encodedStr);
        } catch(Exception ex) {
            ex.printStackTrace();
        }
    }
    X509CRL loadCrl(String filePath) {
        X509CRL crl = null;
        try(InputStream fis = new FileInputStream(filePath)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            crl = (X509CRL) cf.generateCRL(fis);
        } catch(Exception ex) {
            ex.printStackTrace();
        }
        return crl;
    }
}
