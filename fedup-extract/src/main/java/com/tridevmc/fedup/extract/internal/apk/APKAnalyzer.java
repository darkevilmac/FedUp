package com.tridevmc.fedup.extract.internal.apk;

import com.google.common.collect.ImmutableList;
import com.tridevmc.fedup.extract.api.apk.IAPKAnalysisResult;
import com.tridevmc.fedup.extract.api.apk.IAPKAnalyzer;
import com.tridevmc.fedup.extract.api.gql.IRedditGQLOperation;
import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import org.tinylog.Logger;
import org.tinylog.TaggedLogger;

import java.io.File;


public class APKAnalyzer implements IAPKAnalyzer {

    private final File apkFile;
    private JadxDecompiler jadx;

    private static final TaggedLogger LOG = Logger.tag(APKAnalyzer.class.getCanonicalName());

    public APKAnalyzer(File apkFile) {
        this.apkFile = apkFile;
    }

    @Override
    public IAPKAnalysisResult analyzeAPK() {
        var oAuthClientIdAnalysisStep = new APKAnalysisStepOAuthClientID();
        var gqlOperationAnalysisStep = new APKAnalysisStepGQLOperations();
        var gqlOperations = gqlOperationAnalysisStep.perform(getJadxDecompiler());
        var rawOAuthTokenId = oAuthClientIdAnalysisStep.perform(getJadxDecompiler());
        ImmutableList<IRedditGQLOperation> gqlOperationsImmutable = ImmutableList.copyOf(gqlOperations);
        return new APKAnalysisResult(gqlOperationsImmutable, rawOAuthTokenId);
    }

    private JadxDecompiler getJadxDecompiler() {
        if (this.jadx == null) {
            var jadxArgs = new JadxArgs();
            jadxArgs.setInputFile(
                    this.apkFile
            );
            jadxArgs.setOutDir(
                    new File("jadx-out")
            );
            var jadx = new JadxDecompiler(jadxArgs);
            jadx.load();
            jadx.save();
            this.jadx = jadx;
        }
        return this.jadx;
    }

}
