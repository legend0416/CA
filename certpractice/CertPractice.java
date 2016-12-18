/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package certpractice;


import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.*;
import static org.bouncycastle.asn1.x509.Extension.*;
import org.bouncycastle.asn1.x509.KeyUsage;
import static org.bouncycastle.asn1.x509.KeyUsage.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
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
        cert = certPractice.loadCert("/Users/catherine/NetBeansProjects/CertPractice/res/full.crt");
        //cert = certPractice.loadCert("C:\\Users\\tas208\\Documents\\Practice\\CertPractice\\src\\resources\\full.crt");
        certPractice.parseCert(cert);
        certPractice.storeCert(cert, "/Users/catherine/NetBeansProjects/CertPractice/res/certPractice.crt");
        //certPractice.storeCert(cert, "C:\\Users\\tas208\\Documents\\Practice\\CertPractice\\certPractice.crt");

    }
    

    void parseCert(X509Certificate cert) {
        int verNum = cert.getVersion();
        System.out.println("Version: " + verNum);
        BigInteger serialNum = cert.getSerialNumber();
        System.out.println( "Serial Number: "+ serialNum.toString() );
        String sigAlg = cert.getSigAlgName();
        System.out.println("Signature Algorithm: " + sigAlg);
        //String sigAlgOID = cert.getSigAlgOID();
        //System.out.println("Signature Algorithm OID: " + sigAlgOID);
        byte[] sigAlgParams = cert.getSigAlgParams();
        System.out.println("Signature Algorithm Parameters: " + sigAlgParams);
        byte[] sig = cert.getSignature();
        DERBitString derStrSig = new DERBitString(sig);
        System.out.println("Signature Values: " + DatatypeConverter.printHexBinary(derStrSig.getBytes()) );
        X500Principal issuer = cert.getIssuerX500Principal();
        System.out.println("Issuer: " + issuer.getName());
        Date notBefore = cert.getNotBefore();
        System.out.println("Not Before: " + notBefore.toString());
        Date notAfter = cert.getNotAfter();
        System.out.println("Not After: " + notAfter.toString());
        X500Principal subject = cert.getSubjectX500Principal();
        System.out.println("Subject: " + subject.getName());
        PublicKey pk = cert.getPublicKey();
        System.out.println("Public Key Algorithm : " + pk.getAlgorithm());
        System.out.println(pk.getClass());
        if(pk instanceof RSAPublicKey) {
            try {
                RSAPublicKey publicKey = (RSAPublicKey) pk;
                System.out.println("Public Key Exponenet: " + publicKey.getPublicExponent());
                System.out.println("Public Key: " + DatatypeConverter.printHexBinary(publicKey.getModulus().toByteArray()));
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        
        
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
            System.out.println("Is empty!!! QAQ");
        } else {
            System.out.println(extSet.size());
        }
        JcaX509ExtensionUtils jcaext = null;
        for(String oid : extSet) {
            if(oid.equals (authorityInfoAccess.getId() ) ) {
                Utils.parseInformationAccess(cert, oid);
            }
            else if(oid.equals(authorityKeyIdentifier.getId() ) ) {
                AuthorityKeyIdentifier authKeyIdentifier = null;
                try {
                    authKeyIdentifier = AuthorityKeyIdentifier.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));  
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                
                if(authKeyIdentifier != null) {
                    System.out.println("Authority Key Identifier: ");
                    String keyID = DatatypeConverter.printHexBinary(authKeyIdentifier.getKeyIdentifier());
                    System.out.println("    KeyIdentifier: "+(keyID != null ? keyID : "null"));
                    GeneralNames authorityCertIssuer = authKeyIdentifier.getAuthorityCertIssuer();
                    if(authorityCertIssuer != null) {
                        //Utils.parseGeneralNames(authorityCertIssuer);
                        authorityCertIssuer.toString();
                    }
                    BigInteger authCertSerialNum = authKeyIdentifier.getAuthorityCertSerialNumber();
                    if(authCertSerialNum != null) {
                        System.out.print("authorityCertSerialNumber: " + authCertSerialNum.toString());
                    }
                } else {
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
                    System.out.println("Basic Constrainsts:");
                    System.out.println("    Certificate Authority: " + bc.isCA());
                    System.out.println("    Path Length Constraint: " + bc.getPathLenConstraint().toString());
                } else {
                    System.out.println("QQ");
                }
            }
            else if (oid.equals(certificatePolicies.getId() ) ) {
                CertificatePolicies certPlc = null;
                try {
                    certPlc = CertificatePolicies .getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                        ex.printStackTrace();
                }
        
                if(certPlc != null) {
                    System.out.println("Certificate Policies:");
                    PolicyInformation[] polyInfos = certPlc.getPolicyInformation();
                    for (PolicyInformation polyInfo: polyInfos) {
                        System.out.println("Policy ID: " + polyInfo.getPolicyIdentifier().getId() + ":" );
                        ASN1Encodable[] policyQualifiers = polyInfo.getPolicyQualifiers().toArray();
                        for(ASN1Encodable policyQualifier: policyQualifiers) {
                            PolicyQualifierInfo policyQInfo = PolicyQualifierInfo.getInstance(policyQualifier.toASN1Primitive() );
                            if(policyQInfo.getPolicyQualifierId().getId().equals(PolicyQualifierId.id_qt_cps.getId()) ) {
                                System.out.println("    Certification Practice Statement(" + PolicyQualifierId.id_qt_cps.getId() + ")");
                                DERIA5String cPSuri = DERIA5String.getInstance(policyQInfo.getQualifier().toASN1Primitive());
                                System.out.println("        " + cPSuri);
                            } else {
                                System.out.println("    User Notice(" + PolicyQualifierId.id_qt_unotice.getId() + ")");
                                UserNotice usrNotice = UserNotice.getInstance(policyQInfo.getQualifier().toASN1Primitive());
                                NoticeReference noticeRef = usrNotice.getNoticeRef();
                                if(noticeRef != null) {
                                    DisplayText organization = noticeRef.getOrganization();
                                    System.out.println(organization.getString());
                                    ASN1Integer[] noticeNumbers = noticeRef.getNoticeNumbers();
                                    for(ASN1Integer noticeNum: noticeNumbers ) {
                                        System.out.println("        " + noticeNum.getValue().toString());
                                    }
                                }
                                DisplayText explicitText = usrNotice.getExplicitText();
                                if(explicitText != null) {
                                    System.out.println("        " + explicitText.getString());
                                }
                            }
                        }
                    }  
                } else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(cRLDistributionPoints.getId() ) ) {
                Utils.parseCRLDistributionPoints(cert, oid);
            }
            else if (oid.equals(extendedKeyUsage.getId())) {
                ExtendedKeyUsage extKeyUsage = null;
                try {
                    extKeyUsage = ExtendedKeyUsage.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(extKeyUsage != null) {
                    System.out.println("Extended Key Usage:");
                    //rfc7299
                    //https://support.microsoft.com/en-us/kb/287547
                    //there're too many oids. QAQ
                    KeyPurposeId[] keyPurposeIds = extKeyUsage.getUsages();
                    for(KeyPurposeId keyPurposeId : keyPurposeIds) {
                        if(keyPurposeId.getId().equals(KeyPurposeId.anyExtendedKeyUsage.getId())) {
                            System.out.println("    Any Extended Key Usage.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_serverAuth.getId())) {
                            System.out.println("    Server Authentication.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_clientAuth.getId())) {
                            System.out.println("    Client Authentication.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_codeSigning.getId())) {
                            System.out.println("    Code Signing.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_emailProtection.getId())) {
                            System.out.println("    Email Protection.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_ipsecEndSystem.getId())) {
                            System.out.println("    IPsec End System.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_ipsecTunnel.getId())) {
                            System.out.println("    IPsec Tunnel.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_ipsecUser.getId())) {
                            System.out.println("    IPsec User.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_timeStamping.getId())) {
                            System.out.println("    Time Stamping.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_OCSPSigning.getId())) {
                            System.out.println("    OCSP Signing.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_dvcs.getId())) {
                            System.out.println("    Data Validation and Certification Server.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_sbgpCertAAServerAuth.getId())) {
                            System.out.println("    sbgpCertAAServerAuth.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_scvp_responder.getId())) {
                            System.out.println("    scvp_responder.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_eapOverPPP.getId())) {
                            System.out.println("    Extensible Authentication Protocol(EAP) Over Point-to-Point Protocol (PPP).");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_eapOverLAN.getId())) {
                            System.out.println("    Extensible Authentication Protocol(EAP) Over LAN.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_scvpServer.getId())) {
                            System.out.println("    Server-Based Certificate Validation Protocol(SCVP) Server.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_scvpClient.getId())) {
                            System.out.println("    Server-Based Certificate Validation Protocol(SCVP) Client.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_ipsecIKE.getId())) {
                            System.out.println("    IPsec Internet Key Exchange(IKE).");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_capwapAC.getId())) {
                            System.out.println("    Control And Provisioning of Wireless Access Points (CAPWAP) AC.");
                        }
                        else if(keyPurposeId.getId().equals(KeyPurposeId.id_kp_capwapWTP.getId())) {
                            System.out.println("    Control And Provisioning of Wireless Access Points (CAPWAP) WTP.");
                        } else {
                            System.out.println("    " + keyPurposeId.getId());
                        }
                    }
                } else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(freshestCRL.getId())) {
                Utils.parseCRLDistributionPoints(cert, oid);
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
                    System.out.println("Inhibit AnyPolicy: " + ihbAnyPoly.toString());
                }
                else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(issuerAlternativeName.getId())) {
                GeneralNames issuerAltName = null;
                try {
                    issuerAltName = GeneralNames.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)) );
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                if(issuerAltName != null) {
                    System.out.println("Issuer Alternative Name: " + issuerAltName.toString());
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
                    System.out.println("Key Usage: ");
                    if(keyUsage.hasUsages(digitalSignature )) {
                        System.out.println("    Digital signature.");
                    }
                    if(keyUsage.hasUsages(nonRepudiation )) {
                        System.out.println("    Non-repudiation.");
                    }
                    if(keyUsage.hasUsages(keyEncipherment )) {
                        System.out.println("    Key Encipherment.");
                    }
                    if(keyUsage.hasUsages(dataEncipherment )) {
                        System.out.println("    Data Encipherment.");
                    }
                    if(keyUsage.hasUsages(keyAgreement )) {
                        System.out.println("    Key Agreement.");
                    }
                    if(keyUsage.hasUsages(keyCertSign )) {
                        System.out.println("    Key Cert Sign.");
                    }
                    if(keyUsage.hasUsages(cRLSign )) {
                        System.out.println("    CRL Sign.");
                    }
                    if(keyUsage.hasUsages(encipherOnly )) {
                        System.out.println("    Encipher Only.");
                    }
                    if(keyUsage.hasUsages(decipherOnly )) {
                        System.out.println("    Decipher Only.");
                    }
                } else {
                    System.out.println("ohhhhhhhh");
                }
            }
            else if (oid.equals(nameConstraints.getId()) ) {
                NameConstraints nameCst = null;
                try {
                    nameCst =  NameConstraints.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(nameCst != null) {
                    System.out.println("Name Constraints:");
                    GeneralSubtree[] permittedSubtrees = nameCst.getPermittedSubtrees();
                    if(permittedSubtrees != null) {
                        for(GeneralSubtree permittedSubtree : permittedSubtrees) {
                            System.out.println("    base: " + permittedSubtree.getBase().toString());
                            System.out.println("    minimum : " + permittedSubtree.getMinimum());
                            System.out.println("    maximum : " + permittedSubtree.getMaximum());
                        }
                    }
                    GeneralSubtree[] excludedSubtrees = nameCst.getExcludedSubtrees();
                    if(excludedSubtrees != null) {
                        for(GeneralSubtree excludedSubtree : excludedSubtrees) {
                            System.out.println("    base: " + excludedSubtree.getBase().toString());
                            System.out.println("    minimum : " + excludedSubtree.getMinimum());
                            System.out.println("    maximum : " + excludedSubtree.getMaximum());
                        }
                    }
                    if(permittedSubtrees == null && excludedSubtrees == null) {
                        try {
                            System.out.println(nameCst.getEncoded());
                        } catch (IOException ex) {
                           ex.printStackTrace();
                        }
                    }
                } else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(policyConstraints.getId())) {
                PolicyConstraints certPlc = null;
                try {
                    certPlc = PolicyConstraints.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(certPlc != null) {
                    System.out.println("Policy Constraints:");
                    System.out.println("    Require Explicit Policy " + certPlc.getRequireExplicitPolicyMapping());
                    System.out.println("    Inhibit Policy Mapping " + certPlc.getInhibitPolicyMapping());
                } else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(policyMappings.getId())) {
                PolicyMappings polyMaps = null;
                try {
                    polyMaps = PolicyMappings.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                
                if(polyMaps != null) {
                    System.out.println("Policy Mappings:" + polyMaps.toString());
                } else {
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
                    System.out.println("Private Key Usage Period:");
                    System.out.println("    Not Before: " + privKeyUsagePid.getNotBefore().getTime());
                    System.out.println("    Not After: " + privKeyUsagePid.getNotAfter().getTime());
                } else {
                    System.out.println("noooooo");
                }
            }

            else if (oid.equals(subjectAlternativeName.getId() ) ) {
                GeneralNames subAltName = null;
                try {
                    subAltName  = GeneralNames.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)) );
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                if(subAltName  != null) {
                    System.out.println("Subject Alternative Name: " + subAltName.toString());
                } else {
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
                } else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(subjectInfoAccess.getId())) {
                Utils.parseInformationAccess(cert, oid);
            }
            else if (oid.equals(subjectKeyIdentifier.getId())) {
                SubjectKeyIdentifier subKeyId = null;
                try {
                    subKeyId = SubjectKeyIdentifier.getInstance(jcaext.parseExtensionValue(cert.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
        
                if(subKeyId != null) {
                    System.out.println("Subject Key Identifier:");
                    String keyID = DatatypeConverter.printHexBinary(subKeyId.getKeyIdentifier() );
                    System.out.println("    SubjectKeyIdentifier: " + (keyID != null ? keyID: "null") );
                } else {
                    System.out.println("noooooo");
                }
            } else{
                System.out.println("Extension Unknown: ");
                System.out.println("\t" + oid);
                System.out.println("\t" + DatatypeConverter.printHexBinary(cert.getExtensionValue(oid)) + "\n");
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
