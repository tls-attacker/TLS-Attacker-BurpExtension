/**
 * TLS-Attacker-BurpExtension
 * 
 * Copyright 2018 Ruhr University Bochum / Hackmanit GmbH
 * 
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0/
 */
package burp;

import de.rub.nds.burp.tlsattacker.gui.UITab;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.WriterAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.filter.ThresholdFilter;
import org.apache.logging.log4j.core.layout.PatternLayout;
import java.io.PrintWriter;
import java.time.LocalTime;
import org.apache.logging.log4j.Logger;

/**
 * The first class called by Burp Suite.
 * This is the starting class for all other functionalities.
 * 
 * @author Nurullah Erinola
 */
public class BurpExtender implements IBurpExtender {

    private static final Logger LOGGER = LogManager.getLogger(BurpExtender.class.getName());
    public static final String EXTENSION_NAME = "TLS-Attacker";
    
    private UITab tab;
    private static PrintWriter stdout;
    private static PrintWriter stderr;

    /**
     * Register all new functions like for the internals and GUI.
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // Set extension name
        callbacks.setExtensionName(EXTENSION_NAME);   
        // Oprain streans
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
    
        LocalTime t = LocalTime.now();
        String time = t.toString().substring(0, t.toString().length()-4);
        stdout.println("+------------------------------+");
        stdout.println("|         TLS-Attacker         |");
        stdout.println("|      Started @ "+time+"      |");
        stdout.println("+------------------------------+");

        // Setup Logger
        System.setProperty("log4j.configurationFile", "de.rub.nds.burp.tlsattacker.log4j2.xml");
        addBurpLogger();

        // Register a new Tab
        tab = new UITab(callbacks);
        LOGGER.info("Tab registered.");
        
        // Register a new context menu item
        callbacks.registerContextMenuFactory(tab.getUiComponent().getScanner());
        
        LOGGER.info("Init. complete.");
    }

    private void addBurpLogger() {
        // currentContext must be set to false
        final LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        final Configuration config = ctx.getConfiguration();

        // use empty string to get config of root logger, LogManager.ROOT_LOGGER_NAME did not work for unknown reasons
        LoggerConfig rootLoggerCfg = config.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);

        PatternLayout layout = PatternLayout.newBuilder().withPattern("%d{HH:mm:ss}{GMT+0} [%t] %-5level: %c{1} - %msg%n%throwable").build();

        // create appender to log <= INFO to burp's stdout writer
        Filter infoFilter = ThresholdFilter.createFilter(Level.WARN, Filter.Result.DENY, Filter.Result.ACCEPT);
        WriterAppender stdoutAppender = WriterAppender.newBuilder().setName("stdoutLogger").setTarget(stdout)
                .setLayout(layout).setFilter(infoFilter).build();
        stdoutAppender.start();

        // create appender to log >= INFO to burp's sterr writer
        Filter warnFilter = ThresholdFilter.createFilter(Level.WARN, Filter.Result.ACCEPT, Filter.Result.DENY);
        WriterAppender stderrAppender = WriterAppender.newBuilder().setName("stderrLogger").setTarget(stderr)
                .setLayout(layout).setFilter(warnFilter).build();
        stderrAppender.start();

        rootLoggerCfg.addAppender(stdoutAppender, null, null);
        rootLoggerCfg.addAppender(stderrAppender, null, null);

        ctx.updateLoggers();
    }
}
