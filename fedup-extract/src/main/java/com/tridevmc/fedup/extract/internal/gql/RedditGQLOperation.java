package com.tridevmc.fedup.extract.internal.gql;

import com.tridevmc.fedup.extract.api.gql.IRedditGQLOperation;

public record RedditGQLOperation(
        String id,
        String name,
        String definition
) implements IRedditGQLOperation {

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getDefinition() {
        return this.definition;
    }

}
