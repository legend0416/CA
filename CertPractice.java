/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package certpractice;


import java.io.FileInputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.*;
import static org.bouncycastle.asn1.x509.Extension.*;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import sun.security.x509.InhibitAnyPolicyExtension;


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
        int verNum = cert.getVersion();
        System.out.println("Version: " + verNum);
        BigInteger serialNum = cert.getSerialNumber();
        System.out.println( "Serial Number: "+ serialNum.toString() );
        String sigAlg = cert.getSigAlgName();
        System.out.println("Signature Algorithm: " + sigAlg);
        String sigAlgOID = cert.getSigAlgOID();
        System.out.println("Signature Algorithm OID: " + sigAlgOID);
        byte[] sigAlgParams = cert.getSigAlgParams();
        System.out.println("Signature Algorithm Parameters: " + sigAlgParams);
        byte[] sig = cert.getSignature();
        System.out.println("Signature Values: " + sig);
        X500Principal issuer = cert.getIssuerX500Principal();
        System.out.println("Issuer: " + issuer.getName());
        Date notBefore = cert.getNotBefore();
        System.out.println("Not Before: " + notBefore.toString());
        Date notAfter = cert.getNotAfter();
        System.out.println("Not After: " + notAfter.toString());
        X500Principal subject = cert.getSubjectX500Principal();
        System.out.println("Subject: " + subject.getName());
        PublicKey pk = cert.getPublicKey();
        System.out.println("Public Key: " + pk.getEncoded());
        
        //------EXTENSIONS------

        boolean[] issuerUID = cert.getIssuerUniqueID();
        if (issuerUID != null) {
            System.out.println("Issuer Unique ID: " + issuerUID);
        }
        boolean[] subjectUID = cert.getSubjectUniqueID();
        if (subjectUID != null) {
            System.out.println("Subject Unique ID: " + subjectUID);
        }
        
        Set<String> extSet = new HashSet<String>();
        extSet.addAll(cert.getCriticalExtensionOIDs());
        extSet.addAll(cert.getNonCriticalExtensionOIDs());
        if(extSet.isEmpty()) {
            System.out.println("Is empty QAQ");
        }
        else {
            System.out.println(extSet.size());
        }
        JcaX509ExtensionUtils jcaext = null;
        for(String oid: extSet) {
            if(oid.equals(auditIdentity.getId() ) ) {
                System.out.println("Get auditIdentity.");
            }
            else if(oid.equals (authorityInfoAccess.getId() ) ) {
                AuthorityInformationAccess authInfo = null;
                try {
                    authInfo = AuthorityInformationAccess .getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
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
            else if(oid.equals(authorityKeyIdentifier.getId() ) ) {
                AuthorityKeyIdentifier authKeyIdentifier = null;
                try {
                    authKeyIdentifier = AuthorityKeyIdentifier.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(authKeyIdentifier != null) {
                    System.out.println("Get Authority Key Identifier.");
                }
                else {
                    System.out.println("gg.");
                }
            }
            else if(oid.equals(basicConstraints.getId() ) ) {
                BasicConstraints bc = null;
                try {
                    bc = BasicConstraints.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(basicConstraints.getId())));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(bc != null) {
                    System.out.println("Get Basic Constrainsts.");
                }
                else {
                    System.out.println("QQ");
                }
            }
            /**
            else if (oid.equals(biometricInfo.getId() ) ) {
            }**/
            else if (oid.equals(certificatePolicies.getId() ) ) {
                CertificatePolicies certPlc = null;
                try {
                    certPlc = CertificatePolicies .getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                        ex.printStackTrace();
                }
        
                if(certPlc != null) {
                    System.out.println("Get Certificate Policies.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(cRLDistributionPoints.getId() ) ) {
                CRLDistPoint crlDP = null;
                try {
                    crlDP  = CRLDistPoint.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(crlDP != null) {
                    System.out.println("Get CRL Distribution Points.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(extendedKeyUsage.getId())) {
                ExtendedKeyUsage extKeyUsage = null;
                try {
                    extKeyUsage = ExtendedKeyUsage.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(extKeyUsage != null) {
                    System.out.println("Get Extended Key Usage.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(freshestCRL.getId())) {
                CRLDistPoint fCRL = null;
                try {
                    fCRL  = CRLDistPoint.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
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
            else if (oid.equals(inhibitAnyPolicy.getId())) {
                ASN1Integer value = null;
                try {
                    value = ASN1Integer.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(value != null) {
                    BigInteger ihbAnyPoly = value.getValue();
                    System.out.println("Get Inhibit AnyPolicy: " + ihbAnyPoly.toString());
                }
                else {
                    System.out.println("noooooo");
                }
            }
            /**
            else if (oid.equals(instructionCode.getId())) {
            }**/
            else if (oid.equals(issuerAlternativeName.getId())) {
                                GeneralNames issuerAltName = null;
                try {
                    issuerAltName = GeneralNames.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)) );
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                if(issuerAltName != null) {
                    System.out.println("Get Issuer Alternative Name.");
                    
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(keyUsage.getId())) {
                KeyUsage keyUsage = null;
                try {
                    keyUsage = KeyUsage.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                        ex.printStackTrace();
                }
        
                if(keyUsage != null) {
                    System.out.println("Get Key Usage.");
                }
                else {
                    System.out.println("ohhhhhhhh");
                }
            }
            /*
            else if (oid.equals(logoType.getId())) {
            }*/
            else if (oid.equals(nameConstraints.getId()) ) {
                 NameConstraints nameCst = null;
                try {
                    nameCst =  NameConstraints.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(nameCst != null) {
                    System.out.println("Get Name Constraints.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            /**
            else if (oid.equals(noRevAvail.getId())) {
            }**/
            else if (oid.equals(policyConstraints.getId())) {
                PolicyConstraints certPlc = null;
                try {
                    certPlc = PolicyConstraints.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(certPlc != null) {
                    System.out.println("Get Policy Constraints.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(policyMappings.getId())) {
                PolicyMappings polyMap = null;
                try {
                    polyMap= PolicyMappings.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                
                if(polyMap != null) {
                    System.out.println("Get Certificate Policies.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(privateKeyUsagePeriod.getId())) {
                PrivateKeyUsagePeriod privKeyUsagePid = null;
                try {
                    privKeyUsagePid = PrivateKeyUsagePeriod.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(privKeyUsagePid != null) {
                    System.out.println("Get Private Key Usage Period.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            /**
            else if (oid.equals(qCStatements.getId() ) ) {
            }**/
            else if (oid.equals(subjectAlternativeName.getId() ) ) {
                GeneralNames subAltName = null;
                try {
                    subAltName  = GeneralNames.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)) );
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                if(subAltName  != null) {
                    System.out.println("Get Issuer Alternative Name.");
                    
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals( subjectDirectoryAttributes.getId() ) ) {
                SubjectDirectoryAttributes subDirAttributes = null;
                try {
                    subDirAttributes = SubjectDirectoryAttributes.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(subDirAttributes != null) {
                    System.out.println("Get Certificate Policies.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(subjectInfoAccess.getId())) {
                System.out.println("***Get Subject Infomation Access");
            }
            else if (oid.equals(subjectKeyIdentifier.getId())) {
                SubjectKeyIdentifier subKeyId = null;
                try {
                    subKeyId = SubjectKeyIdentifier.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(subKeyId != null) {
                    System.out.println("Get Subject Key Identifier.");
                }
                else {
                    System.out.println("noooooo");
                }
            }
            /**
            else if (oid.equals(targetInformation.getId())) {
            }**/
            else{
               System.out.println(oid);
               System.out.println(cert.getExtensionValue(oid));
            }
        }
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
