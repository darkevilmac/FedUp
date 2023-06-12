package com.tridevmc.fedup.extract.api.apk;

import com.tridevmc.fedup.extract.internal.apk.APKAnalyzer;

import java.io.File;

/**
 * Performs analysis on an APK file.
 */
public interface IAPKAnalyzer {

    /**
     * Creates an APK analyzer for the given APK file.
     *
     * @param apkFile the APK file to analyze.
     * @return an APK analyzer for the given APK file.
     */
    static IAPKAnalyzer createFor(File apkFile) {
        return new APKAnalyzer(apkFile);
    }

    /**
     * Analyzes the APK file and returns the result, initial calls to this method may take a while as the APK is decompiled by jadx.
     *
     * @return the result of the APK analysis.
     */
    IAPKAnalysisResult analyzeAPK();

}
