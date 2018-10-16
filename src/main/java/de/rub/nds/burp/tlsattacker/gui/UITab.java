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
 * An additional tab in Burp Suite.
 * 
 * @author Nurullah Erinola
 */
public class UITab implements ITab {

    private UIMain main;
    private final IBurpExtenderCallbacks callbacks;
 
    /**
     * Create a new Tab.
     * @param callbacks
     */
    public UITab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.main = new UIMain(callbacks);
        callbacks.customizeUiComponent(main);
        callbacks.addSuiteTab(this);
    }
    
    /**
     * @return Get the UI component that should be registered at the Burp Suite GUI. 
     */
    @Override
    public Component getUiComponent() {
        return main;
    }

    /**
     * @return Get the headline for the Tab. 
     */
    @Override
    public String getTabCaption() {
        return "TLS-Attacker";
    }
    
}
