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
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.DERBitString;
import static org.bouncycastle.asn1.x509.Extension.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

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
        //X509CRL crl = crlp.loadCrl("C:\\Users\\tas208\\Documents\\Practice\\CRLPractice\\src\\resources\\Securessl_revoke_sha2_2014.crl");
        X509CRL crl = crlp.loadCrl("/Users/catherine/NetBeansProjects/CRLPractice.java/res/Securessl_revoke_sha2_2014.crl");
        crlp.parseCrl(crl);
        //crlp.storeCrl(crl, "C:\\Users\\tas208\\Documents\\Practice\\CRLPractice\\haha.crl");
        crlp.storeCrl(crl, "/Users/catherine/NetBeansProjects/CRLPractice.java/res/CRL.crl");
    }
    void parseCrl(X509CRL crl) {
        System.out.println("Version: " + crl.getVersion());
        System.out.println("Signature Algorithm: " + crl.getSigAlgName());
        System.out.println("Signature Algorithm OID: " + crl.getSigAlgOID());
        DERBitString derStrSig = new DERBitString(crl.getSignature());
        System.out.println("Signature Values: " + DatatypeConverter.printHexBinary(derStrSig.getBytes()) );
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
                AuthorityKeyIdentifier authKeyIdentifier = null;
                try {
                    authKeyIdentifier = AuthorityKeyIdentifier.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));  
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
            else if(oid.equals(issuerAlternativeName.getId()) ){
                GeneralNames issuerAltName = null;
                try {
                    issuerAltName = GeneralNames.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)) );
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                if(issuerAltName != null) {
                    System.out.println("Issuer Alternative Name: " + issuerAltName.toString());
                    
                } else {
                    System.out.println("noooooo");
                }
            }
            else if (oid.equals(cRLNumber.getId()) ) {
                Utils.parseCRLNumber(crl, oid);
            }
            else if (oid.equals(deltaCRLIndicator.getId() ) ) {
                Utils.parseCRLNumber(crl, oid);
            }
            else if (oid.equals(invalidityDate.getId())) {
                ASN1GeneralizedTime invldDate = null;
                try {
                    invldDate = ASN1GeneralizedTime.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
                if(invldDate != null) {
                    System.out.println("Invalidity Date: " + invldDate.getTime());
                } else {
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
                    System.out.println("Issuing Distribution Point:");
                    //DistributionPointName distributionPoint
                    if(iDP.onlyContainsUserCerts()) {
                        System.out.println("Only Contains User Certs.");
                    }
                    if(iDP.onlyContainsCACerts()) {
                        System.out.println("Only Contains CA Certs.");   
                    }
                    if(iDP.isIndirectCRL()) {
                        System.out.println("Is Indirect CRL.");
                    }
                    if(iDP.onlyContainsAttributeCerts()) {
                        System.out.println("Only Contains Attribute Certs.");
                    }
                    ReasonFlags onlySomeReasons = iDP.getOnlySomeReasons();
                    if(onlySomeReasons != null) {
                        System.out.println("    Reason Flags:");
                        if((onlySomeReasons.intValue() & onlySomeReasons.unused) > 0) {
                            System.out.println("        Unused");
                        }
                        if((onlySomeReasons.intValue() & onlySomeReasons.keyCompromise) > 0) {
                            System.out.println("        Key Compromise.");
                        }
                        if((onlySomeReasons.intValue() & onlySomeReasons.cACompromise) > 0) {
                            System.out.println("        CA Compromise.");
                        }
                        if((onlySomeReasons.intValue() & onlySomeReasons.affiliationChanged) > 0) {
                            System.out.println("        Affiliation Changed.");
                        }
                        if((onlySomeReasons.intValue() & onlySomeReasons.superseded) > 0) {
                            System.out.println("        Superseded.");
                        }
                        if((onlySomeReasons.intValue() & onlySomeReasons.cessationOfOperation) > 0) {
                            System.out.println("        Cessation Of Operation.");
                        }
                        if((onlySomeReasons.intValue() & onlySomeReasons.certificateHold) > 0) {
                            System.out.println("        Certificate Hold.");
                        }
                        if((onlySomeReasons.intValue() & onlySomeReasons.privilegeWithdrawn) > 0) {
                            System.out.println("        Privilege Withdrawn.");
                        }
                        if((onlySomeReasons.intValue() & onlySomeReasons.aACompromise) > 0) {
                            System.out.println("        AA Compromise.");
                        }
                    }
                } else {
                    System.out.println("noooooo");
                }
            }
            else if(oid.equals(freshestCRL.getId()) ) {
                Utils.parseCRLDistributionPoints(crl, oid);
            }
            else if(oid.equals(authorityInfoAccess.getId()) ) {
                Utils.parseInformationAccess(crl, oid);
            }
            else if (oid.equals(reasonCode.getId() ) ) {
                CRLReason rsCode = null;
                try {
                    rsCode = CRLReason.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
                if(rsCode != null) {
                    System.out.println("Reason Code: " + rsCode.getValue().toString() );
                    
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