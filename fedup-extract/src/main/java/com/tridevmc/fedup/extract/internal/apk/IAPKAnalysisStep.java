package com.tridevmc.fedup.extract.internal.apk;

import jadx.api.JadxDecompiler;

/**
 * Performs a step in the APK analysis process and returns the result.
 *
 * @param <T> the type of the result of the analysis step.
 */
public interface IAPKAnalysisStep<T> {

    T perform(JadxDecompiler jadx);

}
