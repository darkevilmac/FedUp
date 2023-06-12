package com.tridevmc.fedup.extract.api.apk;

import com.google.common.collect.ImmutableList;
import com.tridevmc.fedup.extract.api.gql.IRedditGQLOperation;

/**
 * Represents the result of an APK analysis, containing GQL operations and any other necessary data to build a client
 */
public interface IAPKAnalysisResult {

    /**
     * Gets the GQL operations found in the APK.
     *
     * @return an immutable list of the GQL operations.
     */
    ImmutableList<IRedditGQLOperation> getGQLOperations();

    /**
     * Gets the raw OAuth client ID found in the APK.
     *
     * @return the raw OAuth client ID.
     */
    String getRawOAuthClientId();

}
