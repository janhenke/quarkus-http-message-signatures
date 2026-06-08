package dev.janhenke.quarkus.http.message.signatures.deployment;

import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;

class QuarkusHttpMessageSignaturesProcessor {

    private static final String FEATURE = "quarkus-http-message-signatures";

    @BuildStep
    FeatureBuildItem feature() {
        return new FeatureBuildItem(FEATURE);
    }
}
