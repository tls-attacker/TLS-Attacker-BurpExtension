/**
 * TLS-Attacker-BurpExtension
 * 
 * Copyright 2018 Ruhr University Bochum / Hackmanit GmbH
 * 
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0/
 */
package de.rub.nds.burp.utilities;

import java.awt.Color;

/**
 *
 * @author Nurullah Erinola
 */
public class Colors {
    
    public static final Color BLACK = new Color(0, 0, 0);
    public static final Color LIGHT_ORANGE = new Color(255, 153, 0);
    public static final Color DARK_RED = new Color(204, 0, 0);
    public static final Color DARK_BLUE = new Color(0, 0, 204);
    public static final Color DARK_GREEN = new Color(0, 153, 0);
    public static final Color DARK_VIOLET = new Color(148,0,211);
    
    public static Color getColor(String AnsiColor) {
        switch(AnsiColor) {
            case "\u001B[0m": return BLACK;
            case "\u001B[31m": return DARK_RED;
            case "\u001B[32m": return DARK_GREEN;
            case "\u001B[33m": return LIGHT_ORANGE;
            case "\u001B[34m": return DARK_BLUE;
            case "\u001B[35m": return DARK_VIOLET;
            default: return BLACK;
        }
    }
}
