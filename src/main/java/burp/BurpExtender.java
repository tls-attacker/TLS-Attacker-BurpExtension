/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import de.rub.nds.burp.tlsattacker.gui.UITab;
import java.io.PrintWriter;
import java.time.LocalTime;

/**
 *
 * @author Nurullah Erinola
 */
public class BurpExtender implements IBurpExtender {

    public static final String EXTENSION_NAME = "TLS-Attacker";
    
    private UITab tab;
    private static PrintWriter stdout;
    private static PrintWriter stderr;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        callbacks.setExtensionName(EXTENSION_NAME);        
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
    
        LocalTime t = LocalTime.now();
        String time = t.toString().substring(0, t.toString().length()-4);
        stdout.println("+------------------------------+");
        stdout.println("|         TLS-Attacker         |");
        stdout.println("|      Started @ "+time+"      |");
        stdout.println("+------------------------------+");
        
        tab = new UITab(callbacks);        
    }
    
}
