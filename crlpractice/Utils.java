/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crlpractice;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import static org.bouncycastle.asn1.x509.DistributionPointName.FULL_NAME;
import static org.bouncycastle.asn1.x509.Extension.authorityInfoAccess;
import static org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints;
import static org.bouncycastle.asn1.x509.Extension.cRLNumber;
import static org.bouncycastle.asn1.x509.Extension.deltaCRLIndicator;
import static org.bouncycastle.asn1.x509.Extension.freshestCRL;
import static org.bouncycastle.asn1.x509.Extension.subjectInfoAccess;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

/**
 *
 * @author catherine
 */
public class Utils {
    public static void parseCRLDistributionPoints(X509CRL crl, String oid) {
        JcaX509ExtensionUtils jcaext = null;
        CRLDistPoint crlDP = null;
        try {
            crlDP  = CRLDistPoint.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        if(crlDP != null) {
            if (oid.equals(cRLDistributionPoints.getId()) ){
                System.out.println("CRL Distribution Points:");
            }
            else if(oid.equals(freshestCRL.getId())){
                System.out.println("freshest CRL:");
            }
            DistributionPoint[] distributionPoints = crlDP.getDistributionPoints();
            for(DistributionPoint distributionPoint : distributionPoints) {
                DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
                if( distributionPointName != null) {
                    if(distributionPointName.getType() == FULL_NAME ){
                        GeneralNames fullName = GeneralNames.getInstance(distributionPointName.getName().toASN1Primitive());
                        System.out.println("    Distribution Point Name: " + fullName.toString());
                    } else {
                        RDN nameRelativeToCRLIssuer = RDN.getInstance(distributionPointName.getName().toASN1Primitive());
                        System.out.println("\tnameRelativeToCRLIssuer: " + nameRelativeToCRLIssuer.toString());
                    }
                }
                ReasonFlags reasonFlags = distributionPoint.getReasons();
                if(reasonFlags != null) {
                    System.out.println("    Reason Flags:");
                    if((reasonFlags.intValue() & reasonFlags.unused) > 0) {
                        System.out.println("        Unused");
                    }
                    if((reasonFlags.intValue() & reasonFlags.keyCompromise) > 0) {
                        System.out.println("        Key Compromise.");
                    }
                    if((reasonFlags.intValue() & reasonFlags.cACompromise) > 0) {
                        System.out.println("        CA Compromise.");
                    }
                    if((reasonFlags.intValue() & reasonFlags.affiliationChanged) > 0) {
                        System.out.println("        Affiliation Changed.");
                    }
                    if((reasonFlags.intValue() & reasonFlags.superseded) > 0) {
                        System.out.println("        Superseded.");
                    }
                    if((reasonFlags.intValue() & reasonFlags.cessationOfOperation) > 0) {
                        System.out.println("        Cessation Of Operation.");
                    }
                    if((reasonFlags.intValue() & reasonFlags.certificateHold) > 0) {
                        System.out.println("        Certificate Hold.");
                    }
                    if((reasonFlags.intValue() & reasonFlags.privilegeWithdrawn) > 0) {
                        System.out.println("        Privilege Withdrawn.");
                    }
                    if((reasonFlags.intValue() & reasonFlags.aACompromise) > 0) {
                        System.out.println("        AA Compromise.");
                    }
                }
                GeneralNames cRLIssuer = distributionPoint.getCRLIssuer();
                if(cRLIssuer != null) {
                    System.out.println("\tCRL Issuer: " + cRLIssuer.toString());
                }
            }
        } else {
            System.out.println("noooooo");
        }
    }
    public static void parseInformationAccess(X509CRL crl, String oid) {
        JcaX509ExtensionUtils jcaext = null;
        AuthorityInformationAccess authInfo = null;
        try {
            authInfo = AuthorityInformationAccess .getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        if(authInfo != null) {
            if (oid.equals(authorityInfoAccess.getId())) {
                System.out.println("Authority Information Access:");
            }
            else if (oid.equals(subjectInfoAccess.getId())) {
                System.out.println("Subject Information Access:");
            }
            
            AccessDescription[] accessDescriptions = authInfo.getAccessDescriptions();
            for(AccessDescription accessDescription : accessDescriptions) {
                System.out.println("\tAccess Method: " + accessDescription.getAccessMethod().getId());
                System.out.println("\tAccess Location: " + accessDescription.getAccessLocation().toString());

            }
        } else {
            System.out.println("noooooo");
        }
    }
    public static void parseCRLNumber(X509CRL crl, String oid) {
        JcaX509ExtensionUtils jcaext = null;
        CRLNumber crlNum = null;
        try {
            crlNum = CRLNumber.getInstance(jcaext.parseExtensionValue(crl.getExtensionValue(oid)));
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        if(crlNum != null) {
            if(oid.equals(cRLNumber.getId())) {
                System.out.println("CRL Number: " + crlNum.getCRLNumber().toString() );
            }
            else if(oid.equals(deltaCRLIndicator.getId())) {
                System.out.println("Delta CRL Indicator: " + crlNum.getCRLNumber().toString() );
            }
        } else {
            System.out.println("noooooo");
        }
    }
}
