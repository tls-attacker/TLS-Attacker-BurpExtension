/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
        scanner = new UIScanner();    
        this.addTab("Scanner", scanner);
        
        // Customize the UI components
        callbacks.customizeUiComponent(this); 
    } 
    
}
