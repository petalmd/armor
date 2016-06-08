/*
 * Copyright 2016 PetalMD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.petalmd.armor.filter.level;

import java.io.IOException;
import java.util.Map;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.index.query.QueryBuilder;

/**
 *
 * @author jehuty0shift
 */
public class ArmorWrapperQueryBuilder extends QueryBuilder {
    
    private final Map<String,Object> source;
    
    public ArmorWrapperQueryBuilder(Map<String, Object> source){
        this.source = source;
    }
    
    
    @Override
    protected void doXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(ArmorWrapperQueryParser.NAME);
        builder.field("query", source);
        builder.endObject();
    }
    
}
