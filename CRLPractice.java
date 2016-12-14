/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crlpractice;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import static org.bouncycastle.asn1.x509.Extension.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
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
        System.out.println("Version: " + crl.getVersion());
        System.out.println("Signature Algorithm: " + crl.getSigAlgName());
        System.out.println("Signature Algorithm OID: " + crl.getSigAlgOID());
        System.out.println("Signature Value: " + crl.getSignature());
        System.out.println("Issuer Name: " + crl.getIssuerX500Principal().getName());
        System.out.println("This Update: " + crl.getThisUpdate().toString());
        System.out.println("Next Update: " + crl.getNextUpdate().toString());
        /**
        Set<X509CRLEntry> crlEntry = new HashSet<X509CRLEntry>(); 
        crlEntry = (Set<X509CRLEntry>) crl.getRevokedCertificates();
        System.out.println("Get CRL Entry: ");
        for(X509CRLEntry tmp: crlEntry) {
            System.out.println(tmp.getSerialNumber().toString());
        }**/
        Set<String> extSet = new HashSet<String>();
        extSet.addAll(crl.getCriticalExtensionOIDs());
        extSet.addAll(crl.getNonCriticalExtensionOIDs());
        if(extSet.isEmpty()) {
            System.out.println("Is empty QAQ");
        }
        else {
            System.out.println(extSet.size());
        }
        JcaX509ExtensionUtils jcaext = null;
        try {
            jcaext = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
        for(String oid: extSet) {
            if(oid.equals(authorityKeyIdentifier.getId()) ) {
                AuthorityKeyIdentifier authKeyID = null;
                try {
                    authKeyID = AuthorityKeyIdentifier.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)) );
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                if(authKeyID != null) {
                    System.out.println("Get Authority Key Identifier");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if(oid.equals(issuerAlternativeName.getId()) ){
            }
            else if (oid.equals(cRLNumber.getId()) ) {
                CRLNumber crlNum = null;
                try {
                        crlNum = CRLNumber.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
                } catch (Exception ex) {
                        ex.printStackTrace();
                }
        
                if(crlNum != null) {
                    System.out.println("Get CRL Number: " + crlNum.getCRLNumber().toString() );
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(deltaCRLIndicator.getId() ) ) {
                CRLNumber deltaCRLIdtor = null;
                try {
                        deltaCRLIdtor = CRLNumber.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
                } catch (Exception ex) {
                        ex.printStackTrace();
                }
        
                if(deltaCRLIdtor != null) {
                    System.out.println("Get Delta CRL Indicator.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(invalidityDate.getId())) {
                ASN1GeneralizedTime invldDate = null;
                try {
                    invldDate = ASN1GeneralizedTime.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                if(invldDate != null) {
                    System.out.println("Get Invalidity Date: " + invldDate.getTime());
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(issuingDistributionPoint.getId())) {
                IssuingDistributionPoint iDP = null;
                try {
                        iDP = IssuingDistributionPoint .getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
                } catch (Exception ex) {
                        ex.printStackTrace();
                }
        
                if(iDP != null) {
                    System.out.println("Get Issuing Distribution Point.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if(oid.equals(freshestCRL.getId()) ) {
                CRLDistPoint fCRL = null;
                try {
                    fCRL  = CRLDistPoint.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(fCRL != null) {
                    System.out.println("Get freshestCRL.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if(oid.equals(authorityInfoAccess.getId()) ) {
                AuthorityInformationAccess authInfo = null;
                try {
                    authInfo = AuthorityInformationAccess.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(authInfo != null) {
                    System.out.println("Get Authority Information Access.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(reasonCode.getId() ) ) {
                CRLReason rsCode = null;
                try {
                    rsCode = CRLReason.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                if(rsCode != null) {
                    System.out.println("Get Reason Code: " + rsCode.getValue().toString() );
                    
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if(oid.equals(certificateIssuer.getId()) ) {
                GeneralNames certIssuer = null;
                try {
                    certIssuer = GeneralNames.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)) );
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                if(certIssuer != null) {
                    System.out.println("Get Certificate Issuer: " + certIssuer.getNames().toString());
                    
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else {
                System.out.println(oid);
                System.out.println(crl.getExtensionValue(oid));
            }
        }
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
