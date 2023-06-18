package com.tridevmc.fedup.extract.internal.cli;


import com.google.gson.GsonBuilder;
import com.tridevmc.fedup.extract.api.apk.IAPKAnalyzer;
import org.tinylog.Logger;
import org.tinylog.TaggedLogger;
import org.tinylog.configuration.Configuration;
import picocli.CommandLine;
import picocli.CommandLine.Command;

import java.io.File;
import java.nio.file.Files;
import java.util.concurrent.Callable;

@Command(name = "extract", description = "Extracts data from an APK and exports it to the given JSON file or stdout.")
public class CommandExtract implements Callable<Integer> {

    @CommandLine.Option(names = {"-i", "--input"}, description = "The APK to extract data from.", required = true)
    private String input;

    @CommandLine.Option(names = {"-o", "--output"}, description = "The JSON file to export data to. If not specified, will export to stdout.", required = false)
    private String output;

    @Override
    public Integer call() throws Exception {
        var exportToStdout = this.output == null;
        var inputFile = new File(this.input);
        TaggedLogger LOG = null;
        if (!exportToStdout) {
            LOG = Logger.tag("fedup-extract");
        }
        if (inputFile.exists()) {
            if (inputFile.getName().endsWith(".apk")) {
                if (exportToStdout) {
                    // Set the tinylog logging level to OFF to prevent any logging from being output to stdout.
                    Configuration.set("level", "off");
                    var out = this.generateOutputString(inputFile);
                    System.out.println(out);
                } else {
                    var outputFile = new File(this.output);
                    if (outputFile.exists()) {
                        LOG.info("Output file already exists, please select a different output file.");
                        return 1;
                    }
                    var outputString = this.generateOutputString(inputFile);
                    Files.writeString(outputFile.toPath(), outputString);
                }
                return 0;
            } else {
                LOG.info("Input file is not an APK.");
                return 1;
            }
        } else {
            LOG.info("Input file does not exist.");
            return 1;
        }
    }

    private String generateOutputString(File inputFile) {
        var analyzer = IAPKAnalyzer.createFor(inputFile);
        var result = analyzer.analyzeAPK();
        var gson = new GsonBuilder().setPrettyPrinting().create();
        return gson.toJson(result);
    }

}
