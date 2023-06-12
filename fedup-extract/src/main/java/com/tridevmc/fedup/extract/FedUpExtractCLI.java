package com.tridevmc.fedup.extract;

import com.tridevmc.fedup.extract.internal.cli.CommandExtract;
import picocli.CommandLine;

public class FedUpExtractCLI {

    public static void main(String[] args) {
        int exitCode = new CommandLine(new CommandExtract()).execute(args);
        System.exit(exitCode);
    }

}