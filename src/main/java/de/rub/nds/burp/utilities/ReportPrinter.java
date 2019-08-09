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
import javax.swing.JTextPane;
import javax.swing.text.AttributeSet;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyleContext;

/**
 * Printer for the SiteReport.
 * 
 * @author Nurullah Erinola
 */
public class ReportPrinter {

    private final String report;
    private final JTextPane pane;

    public ReportPrinter(JTextPane pane, String report) {
        this.pane = pane;
        this.report = report;
        pane.setContentType("text/html");
        pane.setText("<html>This text box has <b>bold text</b> in it!</html>");
    }
    
    public void print() {
        // Clear textpane
        pane.setText("");

        Color colorCurrent = Colors.BLACK;

        int currentPos = 0; // current char position in addString
        int startIndex = 0; // start of escape sequence
        int endIndex = 0; // end of escape sequence
        
        String tmp = "";
        
        if (report.length() > 0) {
            // Search start of escape sequence
            startIndex = report.indexOf("\u001B");
            // No escape sequence found, print all
            if (startIndex == -1) {
                append(colorCurrent, report);
                return;
            }
            // Escape sequence is not first char, print all text to escape sequence
            if (startIndex > 0) {
                tmp = report.substring(0, startIndex);
                append(colorCurrent, tmp);
                currentPos = startIndex;
            }
            
            while (true) {
                // Search the end of the escape sequence
                endIndex = report.indexOf("m", currentPos);
                
                // End of escape sequence not found, print all
                if (endIndex == -1) {
                    append(colorCurrent, report.substring(currentPos, report.length()));
                    break;
                } else {
                    tmp = report.substring(currentPos, endIndex+1);
                    colorCurrent = Colors.getColor(tmp);
                }
                currentPos = endIndex+1;
                
                // Search start of next escape sequence
                startIndex = report.indexOf("\u001B", currentPos);

                // No further escape sequence available, print all
                if (startIndex == -1) { 
                    tmp = report.substring(currentPos, report.length());
                    append(colorCurrent, tmp);
                    break;
                } else {                
                    tmp = report.substring(currentPos, startIndex);
                    currentPos = startIndex;
                    append(colorCurrent, tmp);
                }
            }
        }
    }
       
    private void append(Color color, String string) {
        pane.setEditable(true);
        
        StyleContext sc = StyleContext.getDefaultStyleContext();
        AttributeSet aset = sc.addAttribute(SimpleAttributeSet.EMPTY, StyleConstants.Foreground, color);
        int len = pane.getDocument().getLength();
        pane.setCaretPosition(len); 
        pane.setCharacterAttributes(aset, false);
        pane.replaceSelection(string);
        
        pane.setEditable(false);
    }

    private void append(String string) {
        append(Color.BLACK, string);
    }
}
