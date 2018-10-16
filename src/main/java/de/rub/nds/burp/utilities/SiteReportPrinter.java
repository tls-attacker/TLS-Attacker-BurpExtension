/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.burp.utilities;

import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import static de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType.NOT_VULNERABLE;
import static de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType.VULN_EXPLOITABLE;
import static de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType.VULN_NOT_EXPLOITABLE;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.constants.CipherSuiteGrade;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.report.CiphersuiteRater;
import de.rub.nds.tlsscanner.report.PerformanceData;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleTestResult;
import java.awt.Color;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.Date;
import javax.swing.JTextPane;
import javax.swing.text.AttributeSet;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;

/**
 * Printer for the SiteReport.
 * Copied from TLS-Scanner repository. Adapted for javax.swing.JTextPane.
 * 
 * @author Nurullah Erinola
 */
public class SiteReportPrinter {

    private static final Logger LOGGER = LogManager.getLogger(SiteReportPrinter.class.getName());

    private final SiteReport report;
    private final ScannerDetail detail;
    private final JTextPane pane;

    public SiteReportPrinter(JTextPane pane,  SiteReport report, ScannerDetail detail) {
        this.report = report;
        this.detail = detail;
        this.pane = pane;
    }

    public void printFullReport() {
        pane.setText("");
        append("Report for ");
        append(report.getHost());
        append("\n");
        if (report.getServerIsAlive() == Boolean.FALSE) {
            append("Cannot reach the Server. Is it online?");
            return;
        }
        if (report.getSupportsSslTls() == Boolean.FALSE) {
            append("Server does not seem to support SSL / TLS on the scanned port");
            return;
        }

        appendProtocolVersions();
        appendCipherSuites();
        appendExtensions();
        appendCompressions();
        appendIntolerances();
        appendAttackVulnerabilities();
        appendGcm();
        appendRfc();
        appendCertificate();
        appendSession();
        appendRenegotiation();
        appendHttps();
        for (PerformanceData data : report.getPerformanceList()) {
            LOGGER.debug("Type: " + data.getType() + "   Start: " + data.getStarttime() + "    Stop: " + data.getStoptime());
        }
    }

    private void appendRfc() {
        prettyAppendHeading("RFC");
        prettyAppendCheckPattern("Checks MAC (AppData)", report.getMacCheckPatternAppData());
        prettyAppendCheckPattern("Checks MAC (Finished)", report.getMacCheckPatternFinished());
        prettyAppendCheckPattern("Checks VerifyData", report.getVerifyCheckPattern());
    }

    private void appendRenegotiation() {
        prettyAppendHeading("Renegotioation & SCSV");
        prettyAppendYellowOnSuccess("Clientside Secure", report.getSupportsClientSideSecureRenegotiation());
        prettyAppendRedOnSuccess("Clientside Insecure", report.getSupportsClientSideInsecureRenegotiation());
        prettyAppendRedOnFailure("SCSV Fallback", report.getTlsFallbackSCSVsupported());        
    }

    private void appendCertificate() {
        if (report.getCertificateReports() != null && !report.getCertificateReports().isEmpty()) {
            prettyAppendHeading("Certificates");
            for (CertificateReport report : report.getCertificateReports()) {
                prettyAppend("Fingerprint", report.getSHA256Fingerprint());
                if (report.getSubject() != null) {
                    prettyAppend("Subject", report.getSubject());
                }
                if (report.getCommonNames() != null) {
                    prettyAppend("CommonNames", report.getCommonNames());
                }
                if (report.getAlternativenames() != null) {
                    prettyAppend("AltNames", report.getAlternativenames());
                }
                if (report.getValidFrom() != null) {
                    if(report.getValidFrom().before(new Date())){
                        prettyAppendGreen("Valid From", report.getValidFrom().toString());
                    } else {
                        prettyAppendRed("Valid From", report.getValidFrom().toString());
                    }
                }
                if (report.getValidTo() != null) {
                    if(report.getValidTo().after(new Date())){
                        prettyAppendGreen("Valid Till", report.getValidTo().toString());
                    } else {
                        prettyAppendRed("Valid Till", report.getValidTo().toString());
                    }
              
                }
                if (report.getPublicKey()!= null) {
                    prettyAppend("PublicKey", report.getPublicKey().toString());
                }
                if (report.getWeakDebianKey()!= null) {
                    prettyAppendRedGreen("Weak Debian Key", report.getWeakDebianKey());
                }
                if (report.getIssuer()!= null) {
                    prettyAppend("Issuer", report.getIssuer());
                }
                if (report.getSignatureAndHashAlgorithm()!= null) {
                    prettyAppend("Signature Algorithm", report.getSignatureAndHashAlgorithm().getSignatureAlgorithm().name());
                }
                if (report.getSignatureAndHashAlgorithm() != null) {
                    if(report.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.SHA1 || report.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.MD5){
                        prettyAppendRed("Hash Algorithm", report.getSignatureAndHashAlgorithm().getHashAlgorithm().name());
                    } else {
                        prettyAppendGreen("Hash Algorithm", report.getSignatureAndHashAlgorithm().getHashAlgorithm().name());
                    }
                }
                if (report.getExtendedValidation()!= null) {
                    prettyAppendGreenOnSuccess("Extended Validation",report.getExtendedValidation());
                }
                if (report.getCertificateTransparency()!= null) {
                    prettyAppendGreenYellow("Certificate Transparency", report.getCertificateTransparency());
                }
                if (report.getOcspMustStaple()!= null) {
                    prettyAppend("OCSP must Staple", report.getOcspMustStaple());
                }
                if (report.getCrlSupported()!= null) {
                    prettyAppendGreenOnSuccess("CRL Supported", report.getCrlSupported());
                }
                if (report.getOcspSupported()!= null) {
                    prettyAppendGreenYellow("OCSP Supported", report.getOcspSupported());
                }
                if (report.getRevoked()!= null) {
                    prettyAppendRedGreen("Is Revoked", report.getRevoked());
                }
                if (report.getDnsCAA()!= null) {
                    prettyAppendGreenOnSuccess("DNS CCA", report.getDnsCAA());
                }
                if (report.getTrusted()!= null) {
                    prettyAppendGreenOnSuccess("Trusted", report.getTrusted());
                }
                if (report.getRocaVulnerable()!= null) {
                    prettyAppendRedGreen("ROCA (simple)", report.getRocaVulnerable());
                } else {
                    append("ROCA (simple): not tested");
                }
            }
            prettyAppendHeading("Certificate Checks");
            prettyAppendRedOnSuccess("Expired Certificates", report.getCertificateExpired());
            prettyAppendRedOnSuccess("Not yet Valid Certificates", report.getCertificateNotYetValid());
            prettyAppendRedOnSuccess("Weak Hash Algorithms", report.getCertificateHasWeakHashAlgorithm());
            prettyAppendRedOnSuccess("Weak Signature Algorithms ", report.getCertificateHasWeakSignAlgorithm());
            prettyAppendRedOnFailure("Matches Domain", report.getCertificateMachtesDomainName());
            prettyAppendGreenOnSuccess("Only Trusted", report.getCertificateIsTrusted());
            prettyAppendRedOnFailure("Contains Blacklisted", report.getCertificateKeyIsBlacklisted());
        }
        
    }

    private void appendSession() {
        prettyAppendHeading("Session");
        prettyAppendGreenYellow("Supports Session resumption", report.getSupportsSessionIds());
        prettyAppendGreenYellow("Supports Session Tickets", report.getSupportsSessionTicket());
        prettyAppend("Session Ticket Hint", report.getSessionTicketLengthHint());
        prettyAppendYellowOnFailure("Session Ticket Rotation", report.getSessionTicketGetsRotated());
        prettyAppendRedOnFailure("Ticketbleed", report.getVulnerableTicketBleed());
        
    }

    private void appendGcm() {
        prettyAppendHeading("GCM");
        prettyAppendRedOnFailure("GCM Nonce reuse", report.getGcmReuse());
        if (null == report.getGcmPattern()) {
            prettyAppend("GCM Pattern");
        } else {
            switch (report.getGcmPattern()) {
                case AKWARD:
                    prettyAppendYellow(addIndentations("GCM Pattern") + report.getGcmPattern().name());
                    break;
                case INCREMENTING:
                case RANDOM:
                    prettyAppendGreen(addIndentations("GCM Pattern") + report.getGcmPattern().name());
                    break;
                case REPEATING:
                    prettyAppendRed(addIndentations("GCM Pattern") + report.getGcmPattern().name());
                    break;
                default:
                    prettyAppend(addIndentations("GCM Pattern") + report.getGcmPattern().name());
                    break;
            }
        }
        prettyAppendRedOnFailure("GCM Check", report.getGcmCheck());
        
    }

    private void appendIntolerances() {
        prettyAppendHeading("Common Bugs [EXPERIMENTAL]");
        prettyAppendRedGreen("Version Intolerant", report.getVersionIntolerance());
        prettyAppendRedGreen("Ciphersuite Intolerant", report.getCipherSuiteIntolerance());
        prettyAppendRedGreen("Extension Intolerant", report.getExtensionIntolerance());
        prettyAppendRedGreen("CS Length Intolerant (>512 Byte)", report.getCipherSuiteLengthIntolerance512());
        prettyAppendRedGreen("Compression Intolerant", report.getCompressionIntolerance());
        prettyAppendRedGreen("ALPN Intolerant", report.getAlpnIntolerance());
        prettyAppendRedGreen("CH Length Intolerant", report.getClientHelloLengthIntolerance());
        prettyAppendRedGreen("NamedGroup Intolerant", report.getNamedGroupIntolerant());
        prettyAppendRedGreen("Empty last Extension Intolerant", report.getEmptyLastExtensionIntolerance());
        prettyAppendRedGreen("SigHashAlgo Intolerant", report.getNamedSignatureAndHashAlgorithmIntolerance());
        prettyAppendRedGreen("Big ClientHello Intolerant", report.getMaxLengthClientHelloIntolerant());
        prettyAppendRedGreen("2nd Ciphersuite Byte Bug", report.getOnlySecondCiphersuiteByteEvaluated());
        prettyAppendRedGreen("Ignores offered Ciphersuites", report.getIgnoresCipherSuiteOffering());
        prettyAppendRedGreen("Reflects offered Ciphersuites", report.getReflectsCipherSuiteOffering());
        prettyAppendRedGreen("Ignores offered NamedGroups", report.getIgnoresOfferedNamedGroups());
        prettyAppendRedGreen("Ignores offered SigHashAlgos", report.getIgnoresOfferedSignatureAndHashAlgorithms());
        
    }

    private void appendAttackVulnerabilities() {
        prettyAppendHeading("Attack Vulnerabilities");
        prettyAppendRedGreen("Padding Oracle", report.getPaddingOracleVulnerable());
        prettyAppendRedGreen("Bleichenbacher", report.getBleichenbacherVulnerable());
        prettyAppendRedGreen("CRIME", report.getCrimeVulnerable());
        prettyAppendRedGreen("Breach", report.getBreachVulnerable());
        prettyAppendRedGreen("Invalid Curve", report.getInvalidCurveVulnerable());
        prettyAppendRedGreen("Invalid Curve Ephemerals", report.getInvalidCurveEphermaralVulnerable());
        prettyAppendRedGreen("SSL Poodle", report.getPoodleVulnerable());
        prettyAppendRedGreen("TLS Poodle", report.getTlsPoodleVulnerable());
        prettyAppendRedGreen("CVE-20162107", report.getCve20162107Vulnerable());
        prettyAppendRedGreen("Logjam", report.getLogjamVulnerable());
        prettyAppendRedGreen("Sweet 32", report.getSweet32Vulnerable());
        prettyAppendDrown("DROWN", report.getDrownVulnerable());
        prettyAppendRedGreen("Heartbleed", report.getHeartbleedVulnerable());
        prettyAppendEarlyCcs("EarlyCcs", report.getEarlyCcsVulnerable());
        prettyAppendHeading("PaddingOracle Details");
        if (report.getPaddingOracleTestResultList() == null || report.getPaddingOracleTestResultList().isEmpty()) {
            prettyAppend("No Testresults");
        } else {
            for (PaddingOracleTestResult testResult : report.getPaddingOracleTestResultList()) {
                String resultString = "" + padToLength(testResult.getSuite().name(), 40) + ":" + testResult.getVersion() + "\t" + testResult.getVectorGeneratorType() + "\t" + testResult.getRecordGeneratorType();
                if (testResult.getVulnerable() == Boolean.TRUE) {
                    prettyAppendRed(resultString + "\t - " + testResult.getEqualityError() + "  VULNERABLE");
                } else if (testResult.getVulnerable() == Boolean.FALSE) {
                    prettyAppendGreen(resultString + "\t - No Behavior Difference");
                } else {
                    prettyAppendYellow(resultString + "\t # Error during Scan");
                }

                if (detail == ScannerDetail.DETAILED || detail == ScannerDetail.ALL) {
                    if (testResult.getEqualityError() != EqualityError.NONE || detail == ScannerDetail.ALL) {
                        prettyAppendYellow("Response Map");
                        if (testResult.getResponseMap() != null && testResult.getResponseMap().get(0) != null) {
                            for (ResponseFingerprint fingerprint : testResult.getResponseMap().get(0)) {
                                prettyAppend("\t" + fingerprint.toString());
                            }
                        } else {
                            prettyAppend("\tNULL");
                        }
                    }
                }
            }
        }
        
    }

    private void appendCipherSuites() {
        if (report.getCipherSuites() != null) {
            prettyAppendHeading("Supported Ciphersuites");
            for (CipherSuite suite : report.getCipherSuites()) {
                prettyPrintCipherSuite(suite);
            }

            for (VersionSuiteListPair versionSuitePair : report.getVersionSuitePairs()) {
                prettyAppendHeading("Supported in " + versionSuitePair.getVersion());
                for (CipherSuite suite : versionSuitePair.getCiphersuiteList()) {
                    prettyPrintCipherSuite(suite);
                }
            }
            if (report.getSupportedTls13CipherSuites() != null && report.getSupportedTls13CipherSuites().size() > 0) {
                prettyAppendHeading("Supported in TLS13");
                for (CipherSuite suite : report.getSupportedTls13CipherSuites()) {
                    prettyPrintCipherSuite(suite);
                }
            }
            prettyAppendHeading("Symmetric Supported");
            prettyAppendRedOnSuccess("Null", report.getSupportsNullCiphers());
            prettyAppendRedOnSuccess("Export", report.getSupportsExportCiphers());
            prettyAppendRedOnSuccess("Anon", report.getSupportsAnonCiphers());
            prettyAppendRedOnSuccess("DES", report.getSupportsDesCiphers());
            prettyAppendYellowOnSuccess("SEED", report.getSupportsSeedCiphers());
            prettyAppendYellowOnSuccess("IDEA", report.getSupportsIdeaCiphers());
            prettyAppendRedOnSuccess("RC2", report.getSupportsRc2Ciphers());
            prettyAppendRedOnSuccess("RC4", report.getSupportsRc4Ciphers());
            prettyAppendYellowOnSuccess("3DES", report.getSupportsTrippleDesCiphers());
            prettyAppend("AES", report.getSupportsAes());
            prettyAppend("CAMELLIA", report.getSupportsCamellia());
            prettyAppend("ARIA", report.getSupportsAria());
            prettyAppendGreenOnSuccess("CHACHA20 POLY1305", report.getSupportsChacha());

            prettyAppendHeading("KeyExchange Supported");
            prettyAppendYellowOnSuccess("RSA", report.getSupportsRsa());
            prettyAppend("DH", report.getSupportsDh());
            prettyAppend("ECDH", report.getSupportsEcdh());
            prettyAppendYellowOnSuccess("GOST", report.getSupportsGost());
            prettyAppend("SRP", report.getSupportsSrp());
            prettyAppend("Kerberos", report.getSupportsKerberos());
            prettyAppend("Plain PSK", report.getSupportsPskPlain());
            prettyAppend("PSK RSA", report.getSupportsPskRsa());
            prettyAppend("PSK DHE", report.getSupportsPskDhe());
            prettyAppend("PSK ECDHE", report.getSupportsPskEcdhe());
            prettyAppendYellowOnSuccess("Fortezza", report.getSupportsFortezza());
            prettyAppendGreenOnSuccess("New Hope", report.getSupportsNewHope());
            prettyAppendGreenOnSuccess("ECMQV", report.getSupportsEcmqv());

            prettyAppendHeading("Perfect Forward Secrecy");
            prettyAppendGreenOnSuccess("Supports PFS", report.getSupportsPfsCiphers());
            prettyAppendGreenOnSuccess("Prefers PFS", report.getPrefersPfsCiphers());
            prettyAppendGreenOnSuccess("Supports Only PFS", report.getSupportsOnlyPfsCiphers());

            prettyAppendHeading("Cipher Types Supports");
            prettyAppend("Stream", report.getSupportsStreamCiphers());
            prettyAppend("Block", report.getSupportsBlockCiphers());
            prettyAppendGreenOnSuccess("AEAD", report.getSupportsAeadCiphers());

            prettyAppendHeading("Ciphersuite General");
            prettyAppendGreenRed("Enforces Ciphersuite ordering", report.getEnforcesCipherSuiteOrdering());
        }
        
    }

    private void appendProtocolVersions() {
        if (report.getVersions() != null) {
            prettyAppendHeading("Supported Protocol Versions");
            for (ProtocolVersion version : report.getVersions()) {
                append(version.name());
                append("\n");
            }
            prettyAppendHeading("Versions");
            prettyAppendRedGreen("SSL 2.0", report.getSupportsSsl2());
            prettyAppendRedGreen("SSL 3.0", report.getSupportsSsl3());
            prettyAppendYellowOnFailure("TLS 1.0", report.getSupportsTls10());
            prettyAppendYellowOnFailure("TLS 1.1", report.getSupportsTls11());
            prettyAppendRedOnFailure("TLS 1.2", report.getSupportsTls12());
            prettyAppendGreenOnSuccess("TLS 1.3", report.getSupportsTls13());
            prettyAppendYellowOnSuccess("TLS 1.3 Draft 14", report.getSupportsTls13Draft14());
            prettyAppendYellowOnSuccess("TLS 1.3 Draft 15", report.getSupportsTls13Draft15());
            prettyAppendYellowOnSuccess("TLS 1.3 Draft 16", report.getSupportsTls13Draft16());
            prettyAppendYellowOnSuccess("TLS 1.3 Draft 17", report.getSupportsTls13Draft17());
            prettyAppendGreenOnSuccess("TLS 1.3 Draft 18", report.getSupportsTls13Draft18());
            prettyAppendGreenOnSuccess("TLS 1.3 Draft 19", report.getSupportsTls13Draft19());
            prettyAppendGreenOnSuccess("TLS 1.3 Draft 20", report.getSupportsTls13Draft20());
            prettyAppendGreenOnSuccess("TLS 1.3 Draft 21", report.getSupportsTls13Draft21());
            prettyAppendGreenOnSuccess("TLS 1.3 Draft 22", report.getSupportsTls13Draft22());
            prettyAppendGreenOnSuccess("TLS 1.3 Draft 23", report.getSupportsTls13Draft23());
            prettyAppendGreenOnSuccess("TLS 1.3 Draft 24", report.getSupportsTls13Draft24());
            prettyAppendGreenOnSuccess("TLS 1.3 Draft 25", report.getSupportsTls13Draft25());
            prettyAppendGreenOnSuccess("TLS 1.3 Draft 26", report.getSupportsTls13Draft26());
            prettyAppendGreenOnSuccess("TLS 1.3 Draft 27", report.getSupportsTls13Draft27());
            prettyAppendGreenOnSuccess("TLS 1.3 Draft 28", report.getSupportsTls13Draft28());
            //prettyAppend("DTLS 1.0", report.getSupportsDtls10());
            //prettyAppend("DTLS 1.2", report.getSupportsDtls10());
            //prettyAppend("DTLS 1.3", report.getSupportsDtls13());
        }
        
    }

    private void appendHttps() {
        if (report.getSpeaksHttps() == Boolean.TRUE) {
            prettyAppendHeading("HSTS");
            if (report.getSupportsHsts() == Boolean.TRUE) {
                prettyAppendGreenOnSuccess("HSTS", report.getSupportsHsts());
                prettyAppendGreenOnSuccess("HSTS Preloading", report.getSupportsHstsPreloading());
                prettyAppend("max-age (seconds)", (long) report.getHstsMaxAge());
            } else {
                prettyAppend("Not supported");
            }
            prettyAppendHeading("HPKP");
            if (report.getSupportsHpkp() == Boolean.TRUE || report.getSupportsHpkpReportOnly() == Boolean.TRUE) {
                prettyAppendGreenOnSuccess("HPKP", report.getSupportsHpkp());
                prettyAppendGreenOnSuccess("HPKP (report only)", report.getSupportsHpkpReportOnly());
                prettyAppend("max-age (seconds)", (long) report.getHpkpMaxAge());
                if (report.getNormalHpkpPins().size() > 0) {
                    prettyAppend("");
                    prettyAppendGreen("HPKP-Pins:");
                    for (HpkpPin pin : report.getNormalHpkpPins()) {
                        prettyAppend(pin.toString());
                    }
                }
                if (report.getReportOnlyHpkpPins().size() > 0) {
                    prettyAppend("");
                    prettyAppendGreen("Report Only HPKP-Pins:");
                    for (HpkpPin pin : report.getReportOnlyHpkpPins()) {
                        prettyAppend(pin.toString());
                    }
                }

            } else {
                prettyAppend("Not supported");
            }
            prettyAppendHeading("HTTPS Response Header");
            for (HttpsHeader header : report.getHeaderList()) {
                prettyAppend(header.getHeaderName().getValue() + ":" + header.getHeaderValue().getValue());
            }
        }
        
    }

    private void appendExtensions() {
        if (report.getSupportedExtensions() != null) {
            prettyAppendHeading("Supported Extensions");
            for (ExtensionType type : report.getSupportedExtensions()) {
                append(type.name());
                append("\n");
            }
        }
        prettyAppendHeading("Extensions");
        prettyAppendGreenRed("Secure Renegotiation", report.getSupportsSecureRenegotiation());
        prettyAppendGreenOnSuccess("Extended Master Secret", report.getSupportsExtendedMasterSecret());
        prettyAppendGreenOnSuccess("Encrypt Then Mac", report.getSupportsEncryptThenMacSecret());
        prettyAppendGreenOnSuccess("Tokenbinding", report.getSupportsTokenbinding());

        if (report.getSupportsTokenbinding() == Boolean.TRUE) {
            prettyAppendHeading("Tokenbinding Version");
            for (TokenBindingVersion version : report.getSupportedTokenBindingVersion()) {
                append(version.toString());
                append("\n");
            }

            prettyAppendHeading("Tokenbinding Key Parameters");
            for (TokenBindingKeyParameters keyParameter : report.getSupportedTokenBindingKeyParameters()) {
                append(keyParameter.toString());
                append("\n");
            }
        }
        appendTls13Groups();
        appendCurves();
        appendSignatureAndHashAlgorithms();
        
    }

    private void prettyPrintCipherSuite(CipherSuite suite) {
        CipherSuiteGrade grade = CiphersuiteRater.getGrade(suite);
        switch (grade) {
            case GOOD:
                prettyAppendGreen(suite.name());
                break;
            case LOW:
                prettyAppendRed(suite.name());
                break;
            case MEDIUM:
                prettyAppendYellow(suite.name());
                break;
            case NONE:
                prettyAppend(suite.name());
                break;
            default:
                prettyAppend(suite.name());
        }
    }

    private void appendCurves() {
        if (report.getSupportedNamedGroups() != null) {
            prettyAppendHeading("Supported Named Groups");
            if (report.getSupportedNamedGroups().size() > 0) {
                for (NamedGroup group : report.getSupportedNamedGroups()) {
                    append(group.name());
                    append("\n");
                }
            } else {
                append("none\n");
            }
        }
        
    }

    private void appendSignatureAndHashAlgorithms() {
        if (report.getSupportedSignatureAndHashAlgorithms() != null) {
            prettyAppendHeading("Supported Signature and Hash Algorithms");
            if (report.getSupportedSignatureAndHashAlgorithms().size() > 0) {
                for (SignatureAndHashAlgorithm algorithm : report.getSupportedSignatureAndHashAlgorithms()) {
                    prettyAppend(algorithm.toString());
                }
            } else {
                append("none\n");
            }
        }
        
    }

    private void appendCompressions() {
        if (report.getSupportedCompressionMethods() != null) {
            prettyAppendHeading("Supported Compressions");
            for (CompressionMethod compression : report.getSupportedCompressionMethods()) {
                prettyAppend(compression.name());
            }
        }
        
    }

    private void prettyAppend(String value) {
        append(value);
        append("\n");
    }
    
    private void prettyAppend(String name, String value) {
        append(addIndentations(name) + ": " + (value == null ? "Unknown" : value) + "\n");
    }

    private void prettyAppend(String name, Long value) {
        append(addIndentations(name) + ": " + (value == null ? "Unknown" : value) + "\n");
    }

    private void prettyAppend(String name, Boolean value) {
        append(addIndentations(name) + ": " + (value == null ? "Unknown" : value.toString()) + "\n");
    }

    private void prettyAppendGreenOnSuccess(String name, Boolean value) {
        append(addIndentations(name) + ": ");
        if(value == null) {
            append("Unknown");
        } else {
            if(value == Boolean.TRUE && report.isNoColour() == false) {
                appendWithColor(Color.GREEN, value.toString());
            } else {
                append(value.toString());
            }
        }
        append("\n");
    }

    private void prettyAppendGreenOnFailure(String name, Boolean value) {
        append(addIndentations(name) + ": ");
        if(value == null) {
            append("Unknown");
        } else {
            if(value == Boolean.FALSE && report.isNoColour() == false) {
                appendWithColor(Color.GREEN, value.toString());
            } else {
                append(value.toString());
            }
        }
        append("\n");
    }

    private void prettyAppendRedOnSuccess(String name, Boolean value) {
        append(addIndentations(name) + ": ");
        if(value == null) {
            append("Unknown");
        } else {
            if(value == Boolean.TRUE && report.isNoColour() == false) {
                appendWithColor(Color.RED, value.toString());
            } else {
                append(value.toString());
            }
        }
        append("\n");
    }

    private void prettyAppendRedOnFailure(String name, Boolean value) {
        append(addIndentations(name) + ": ");
        if(value == null) {
            append("Unknown");
        } else {
            if(value == Boolean.FALSE && report.isNoColour() == false) {
                appendWithColor(Color.RED, value.toString());
            } else {
                append(value.toString());
            }
        }
        append("\n");
    }

    private void prettyAppendYellowOnFailure(String name, Boolean value) {
        append(addIndentations(name) + ": ");
        if(value == null) {
            append("Unknown");
        } else {
            if(value == Boolean.FALSE && report.isNoColour() == false) {
                appendWithColor(Color.YELLOW, value.toString());
            } else {
                append(value.toString());
            }
        }
        append("\n");
    }

    private void prettyAppendYellowOnSuccess(String name, Boolean value) {
        append(addIndentations(name) + ": ");
        if(value == null) {
            append("Unknown");
        } else {
            if(value == Boolean.TRUE && report.isNoColour() == false) {
                appendWithColor(Color.YELLOW, value.toString());
            } else {
                append(value.toString());
            }
        }
        append("\n");
    }

    private void prettyAppendGreenRed(String name, Boolean value) {
        append(addIndentations(name) + ": ");
        if(value == null) {
            append("Unknown");
        } else {
            if(report.isNoColour() == false) {
                if(value == Boolean.TRUE) {
                    appendWithColor(Color.GREEN, value.toString());
                } else {
                    appendWithColor(Color.RED, value.toString());
                }
            } else {
                append(value.toString());
            }
        }
        append("\n");
    }

    private void prettyAppendRedGreen(String name, Boolean value) {
        append(addIndentations(name) + ": ");
        if(value == null) {
            append("Unknown");
        } else {
            if(report.isNoColour() == false) {
                if(value == Boolean.TRUE) {
                    appendWithColor(Color.RED, value.toString());
                } else {
                    appendWithColor(Color.GREEN, value.toString());
                }
            } else {
                append(value.toString());
            }
        }
        append("\n");
    }

    private void prettyAppendGreenYellow(String name, Boolean value) {
        append(addIndentations(name) + ": ");
        if(value == null) {
            append("Unknown");
        } else {
            if(report.isNoColour() == false) {
                if(value == Boolean.TRUE) {
                    appendWithColor(Color.GREEN, value.toString());
                } else {
                    appendWithColor(Color.YELLOW, value.toString());
                }
            } else {
                append(value.toString());
            }
        }
        append("\n");
    }

    private void prettyAppendYellow(String value) {
        if(report.isNoColour() == false) {
            appendWithColor(Color.YELLOW, value);
        } else {
            append(value);
        }
        append("\n");
    }

    private void prettyAppendRed(String value) {
        if(report.isNoColour() == false) {
            appendWithColor(Color.RED, value);
        } else {
            append(value);
        }
        append("\n");
    }
    
    private void prettyAppendRed(String name, String value) {
        append(addIndentations(name) + ": ");
        if(report.isNoColour() == false) {
            appendWithColor(Color.RED, value);
        } else {
            append(value);
        }
        append("\n");
    }

    private void prettyAppendGreen(String value) {
        if(report.isNoColour() == false) {
            appendWithColor(Color.GREEN, value);
        } else {
            append(value);
        }
        append("\n");
    }
    
    private void prettyAppendGreen(String name, String value) {
        append(addIndentations(name) + ": ");
        if(report.isNoColour() == false) {
            appendWithColor(Color.GREEN, value);
        } else {
            append(value);
        }
        append("\n");
    }

    private void prettyAppendHeading(String value) {
        if(report.isNoColour() == false) {
            appendWithColor(Color.blue, "\n--------------------------------------------------------\n" + value + "\n\n");
        } else {
            append("\n--------------------------------------------------------\n" + value + "\n\n");
        }
    }

    private void prettyAppendDrown(String testName, DrownVulnerabilityType drownVulnerable) {
        append(addIndentations(testName));
        append(": ");
        if (drownVulnerable == null) {
            prettyAppend("Unknown");
            return;
        }
        switch (drownVulnerable) {
            case FULL:
                prettyAppendRed("true - fully exploitable");
                break;
            case SSL2:
                prettyAppendRed("true - SSL 2 supported!");
                break;
            case NONE:
                prettyAppendGreen("false");
                break;
            case UNKNOWN:
                prettyAppend("Unknown");
                break;
        }
    }

    private void prettyAppendEarlyCcs(String testName, EarlyCcsVulnerabilityType earlyCcsVulnerable) {
        append(addIndentations(testName));
        append(": ");
        if (earlyCcsVulnerable == null) {
            prettyAppend("Unknown");
            return;
        }
        switch (earlyCcsVulnerable) {
            case VULN_EXPLOITABLE:
                prettyAppendRed("true - exploitable");
                break;
            case VULN_NOT_EXPLOITABLE:
                prettyAppendRed("true - probably not exploitable");
                break;
            case NOT_VULNERABLE:
                prettyAppendGreen("false");
                break;
            case UNKNOWN:
                prettyAppend("Unknown");
                break;
        }
    }

    private void prettyAppendCheckPattern(String value, CheckPattern pattern) {
        if (pattern == null) {
            append(value);
            append(": Unknown\n");
            return;
        }
        append(value);
        append(": ");
        switch (pattern.getType()) {
            case CORRECT:
                prettyAppendGreen(pattern.toString());
            case NONE:
            case PARTIAL:
                prettyAppendRed(pattern.toString());
            case UNKNOWN:
                prettyAppend(pattern.toString());
            default:
                throw new IllegalArgumentException("Unkown MacCheckPattern Type: " + pattern.getType());
        }
    }

    private String padToLength(String value, int length) {
        StringBuilder builder = new StringBuilder(value);
        while (builder.length() < length) {
            builder.append(" ");
        }
        return builder.toString();
    }

    private String addIndentations(String value) {
        StringBuilder builder = new StringBuilder();
        builder.append(value);
        if (value.length() < 8) {
            builder.append("\t\t\t\t ");
        } else if (value.length() < 16) {
            builder.append("\t\t\t ");
        } else if (value.length() < 24) {
            builder.append("\t\t ");
        } else if (value.length() < 32) {
            builder.append("\t ");
        } else {
            builder.append(" ");
        }
        return builder.toString();
    }

    private void appendTls13Groups() {
        if (report.getSupportedTls13Groups() != null) {
            prettyAppendHeading("TLS 1.3 Named Groups");
            if (report.getSupportedTls13Groups().size() > 0) {
                for (NamedGroup group : report.getSupportedTls13Groups()) {
                    append(group.name());
                    append("\n");
                }
            } else {
                append("none\n");
            }
        }
        
    }
    
    private void appendWithColor(Color color, String string) {
        pane.setEditable(true);
        StyleContext sc = StyleContext.getDefaultStyleContext();
        AttributeSet aset = sc.addAttribute(SimpleAttributeSet.EMPTY, StyleConstants.Foreground, color);
        int len = pane.getDocument().getLength(); ;
        pane.setCaretPosition(len); 
        pane.setCharacterAttributes(aset, false);
        pane.replaceSelection(string);
        pane.setEditable(false);
    }

    private void append(String string) {
        appendWithColor(Color.black, string);
    }
}
