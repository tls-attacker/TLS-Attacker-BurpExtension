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
import burp.ITab;

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
    public UIMain getUiComponent() {
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
