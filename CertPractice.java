/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package certpractice;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

/**
 *
 * @author TAS208
 */
public class CertPractice {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        CertPractice certPractice = new CertPractice();
        X509Certificate cert = null;
        cert = certPractice.loadCert("C:\\Users\\tas208\\Documents\\Practice\\CertPractice\\src\\resources\\full.crt");
        certPractice.parseCert(cert);
        certPractice.storeCert(cert, "C:\\Users\\tas208\\Documents\\Practice\\CertPractice\\certPractice.crt");

    }

    void parseCert(X509Certificate cert) {
        BigInteger serialNum = cert.getSerialNumber();
        System.out.println(serialNum.toString());
        int verNum = cert.getVersion();
        System.out.println(verNum);
    }

    void storeCert(X509Certificate cert, String filePath) {
        /**
         * FileOutputStream fw = new FileOutputStream(filePath); byte[]
         * encodedStr = null; byte[] lineSeparator = {'\n'}; try { encodedStr =
         * Base64.getMimeEncoder(64, lineSeparator).encode(cert.getEncoded()); }
         * catch (CertificateEncodingException ex) {
         * Logger.getLogger(CertPractice.class.getName()).log(Level.SEVERE,
         * null, ex); } fw.write(encodedStr); fw.flush(); fw.close();
         *
         */

        try (JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(filePath))) {
            pw.writeObject( new PemObject("CERTIFICATE", cert.getEncoded()));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    X509Certificate loadCert(String filePath) {
        
        X509Certificate cert = null;
        CertificateFactory cf = null;
        try (FileInputStream is = new FileInputStream(filePath)){
            cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(is);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return cert;
    }

}
