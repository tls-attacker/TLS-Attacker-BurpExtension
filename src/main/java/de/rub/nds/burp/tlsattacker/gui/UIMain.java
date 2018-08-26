/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.burp.tlsattacker.gui;

import burp.IBurpExtenderCallbacks;
import javax.swing.JTabbedPane;

/**
 *
 * @author Nurullah Erinola
 */
public class UIMain extends JTabbedPane {
    
    private final IBurpExtenderCallbacks callbacks;
    
    public UIMain(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        initComponents();  
    }
    
    private void initComponents() {
            
    } 
    
}
