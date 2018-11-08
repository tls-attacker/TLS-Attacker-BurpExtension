/**
 * TLS-Attacker-BurpExtension
 * 
 * Copyright 2018 Ruhr University Bochum / Hackmanit GmbH
 * 
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0/
 */
package de.rub.nds.burp.utilities.table;

import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 * A table entry for the class Table.
 * 
 * @author Nurullah Erinola
 */
public class TableEntry {
    
    private ScannerConfig config;
    private SiteReport report;
    private String counter;
    private String host;
    private String danger;
    private String implementation;
    private String noColor;
    private String scanDetail;
    private String reportDetail;

    /**
     * Construct a new table entry.
     */
    public TableEntry(int counter, SiteReport report, ScannerConfig config) {
        this.report = report;
        this.config = config;
        this.host = report.getHost();
        this.counter = Integer.toString(counter);
        this.danger = Integer.toString(config.getDangerLevel());
        this.implementation = Boolean.toString(config.isImplementation());
        this.noColor = Boolean.toString(config.isNoColor());
        this.scanDetail = config.getScanDetail().toString();
        this.reportDetail = config.getReportDetail().toString();
    }
    
    public SiteReport getSiteReport() {
        return report;
    }
    
    public ScannerConfig getConfig() {
        return config;
    }
    
    public String getCounter() {
        return counter;
    }
    
    public String getHost() {
        return host;
    }
    
    public String getDanger() {
        return danger;
    }
    
    public String getImplementation() {
        return implementation;
    }

    public String getNoColor() {
        return noColor;
    }
    
    public String getScanDetail() {
        return scanDetail;
    }
    
    public String getReportDetail() {
        return reportDetail;
    }
}
