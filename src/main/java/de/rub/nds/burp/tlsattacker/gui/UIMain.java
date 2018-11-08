/**
 * TLS-Attacker-BurpExtension
 * 
 * Copyright 2018 Ruhr University Bochum / Hackmanit GmbH
 * 
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0/
 */
package de.rub.nds.burp.tlsattacker.gui;

import burp.IBurpExtenderCallbacks;
import javax.swing.JTabbedPane;

/**
 * The main window.
 * 
 * @author Nurullah Erinola
 */
public class UIMain extends JTabbedPane {
    
    private final IBurpExtenderCallbacks callbacks; 
    private UIScanner scanner;
    private UIScanHistory scanHistory;
 
    /**
     * Construct the main UI.
     * @param callbacks
     */
    public UIMain(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        initComponents();  
    }
    
    private void initComponents() {
        //register all components on the extension tab
        scanHistory = new UIScanHistory();
        scanner = new UIScanner(scanHistory);    
        this.addTab("TLS-Scanner", scanner);
        this.addTab("Scan History", scanHistory);
        
        // Customize the UI components
        callbacks.customizeUiComponent(this); 
    } 
    
    public UIScanner getScanner(){
        return scanner;
    }
}
