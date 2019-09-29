/**
 * TLS-Attacker-BurpExtension
 * 
 * Copyright 2018 Ruhr University Bochum / Hackmanit GmbH
 * 
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0/
 */
package de.rub.nds.burp.utilities;

import de.rub.nds.tlsscanner.constants.AnsiColor;
import java.awt.Color;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import org.apache.commons.lang3.StringUtils;

/**
 * Printer for the SiteReport.
 * 
 * @author Nurullah Erinola
 */
public class ANSIHelper {

    // self defined colors
    private static final Color LIGHT_ORANGE = new Color(255, 153, 0);
    private static final Color DARK_RED = new Color(204, 0, 0);
    private static final Color DARK_BLUE = new Color(0, 0, 204);
    private static final Color DARK_GREEN = new Color(0, 153, 0);
    private static final Color DARK_VIOLET = new Color(148,0,211);
    
    private static final String ANSI_START = "\u001B[";
    private static final String ANSI_END = "m";
           
    public static StyledDocument getStyledDocument(String report) {
        StyledDocument document = new DefaultStyledDocument();
        SimpleAttributeSet attributes = new SimpleAttributeSet();
        
        int currentPos = 0; // current char position in report
        int startIndex = 0; // start of escape sequence
        int endIndex = 0; // end of escape sequence
        
        String tmp = "";
        
        if (report.length() > 0) {
            // Search start of escape sequence
            startIndex = report.indexOf(ANSI_START);
            // No escape sequence found, print all
            if (startIndex == -1) {
                append(document, attributes, report);
                return document;
            }
            // Escape sequence is not first char, print all text to escape sequence
            if (startIndex > 0) {
                tmp = report.substring(0, startIndex);
                document = append(document, attributes, tmp);
                currentPos = startIndex;
            }
            
            while (true) {
                // Search the end of the escape sequence
                endIndex = report.indexOf(ANSI_END, currentPos);
                
                // End of escape sequence not found, print all
                if (endIndex == -1) {
                    document = append(document, attributes, report.substring(currentPos, report.length()));
                    break;
                // End of escape sequence found, parse
                } else {
                    tmp = report.substring(currentPos, endIndex+1);
                    attributes = parseAndAdd(attributes, tmp);
                    currentPos = endIndex+1;
                }
                
                // Search start of next escape sequence
                startIndex = report.indexOf(ANSI_START, currentPos);

                // No further escape sequence available, print all
                if (startIndex == -1) {
                    document = append(document, attributes, report.substring(currentPos, report.length()));
                    break;
                // Further escape sequence available, print substring between escape sequence
                } else {
                    document = append(document, attributes, report.substring(currentPos, startIndex));
                    currentPos = startIndex;
                }
            }
        }
        return document;
    }

    private static String replaceTabs(String string) {
        String[] splitted = string.split("\n", -1);
        for(int i = 0; i < splitted.length; i++) {
            int pos = splitted[i].indexOf("\t");
            while(pos != -1) {
                splitted[i] = splitted[i].replaceFirst("\t", StringUtils.repeat(" ", 8-(pos%8)));
                pos = splitted[i].indexOf("\t");
            }
        }
        return String.join("\n", splitted);
    }

    private static StyledDocument append(StyledDocument document, SimpleAttributeSet attributes, String toAppend) {
        try {
           document.insertString(document.getLength(), replaceTabs(toAppend), attributes);
        } catch (BadLocationException exp) {
            
        }
        return document;
    } 

    private static SimpleAttributeSet parseAndAdd(SimpleAttributeSet attrSet, String ansi) {
        switch(AnsiColor.getAnsiColor(ansi)) {
            case RESET: 
                attrSet = new SimpleAttributeSet();
                break;        
            case BLACK: 
                attrSet.addAttribute(StyleConstants.Foreground, Color.BLACK);
                break;
            case RED: 
                attrSet.addAttribute(StyleConstants.Foreground, DARK_RED);
                break;
            case GREEN: 
                attrSet.addAttribute(StyleConstants.Foreground, DARK_GREEN);
                break;
            case YELLOW: 
                attrSet.addAttribute(StyleConstants.Foreground, LIGHT_ORANGE);
                break;
            case BLUE: 
                attrSet.addAttribute(StyleConstants.Foreground, DARK_BLUE);
                break;
            case PURPLE: 
                attrSet.addAttribute(StyleConstants.Foreground, DARK_VIOLET);
                break;
            case CYAN: 
                attrSet.addAttribute(StyleConstants.Foreground, Color.CYAN);
                break;
            case WHITE: 
                attrSet.addAttribute(StyleConstants.Foreground, Color.WHITE);
                break;
            case BOLD: 
                attrSet.addAttribute(StyleConstants.CharacterConstants.Bold, Boolean.TRUE);
                break;
            case UNDERLINE: 
                StyleConstants.setUnderline(attrSet, true);
                break;
            default: 
                break;
        }
        return attrSet;
    }
}
