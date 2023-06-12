package com.tridevmc.fedup.extract.internal.apk;

import com.google.common.collect.ImmutableList;
import com.tridevmc.fedup.extract.api.apk.IAPKAnalysisResult;
import com.tridevmc.fedup.extract.api.gql.IRedditGQLOperation;

public record APKAnalysisResult(
        ImmutableList<IRedditGQLOperation> gqlOperations,
        String oAuthClientId
) implements IAPKAnalysisResult {

    @Override
    public ImmutableList<IRedditGQLOperation> getGQLOperations() {
        return this.gqlOperations;
    }

    @Override
    public String getRawOAuthClientId() {
        return this.oAuthClientId;
    }

}
