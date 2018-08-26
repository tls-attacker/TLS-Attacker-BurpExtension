/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.burp.tlsattacker.gui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import java.awt.Component;

/**
 *
 * @author Nurullah Erinola
 */
public class UITab implements ITab {

    private UIMain main;
    private final IBurpExtenderCallbacks callbacks;
    
    public UITab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.main = new UIMain(callbacks);
        callbacks.customizeUiComponent(main);
        callbacks.addSuiteTab(this);
    }
    
    @Override
    public Component getUiComponent() {
        return main;
    }
        
    @Override
    public String getTabCaption() {
        return "TLS-Attacker";
    }
    
}
