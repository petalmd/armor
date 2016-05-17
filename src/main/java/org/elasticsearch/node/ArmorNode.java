/*
 * Copyright 2016 bdiasse.
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
package org.elasticsearch.node;

import java.util.Collection;
import org.elasticsearch.Version;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.node.internal.InternalSettingsPreparer;
import org.elasticsearch.plugins.Plugin;

/**
 *
 * @author bdiasse
 */
public final class ArmorNode extends Node {

    public ArmorNode(Settings preparedSettings, Collection<Class<? extends Plugin>> plugins) {
        super(InternalSettingsPreparer.prepareEnvironment(preparedSettings, null), Version.CURRENT, plugins);
    }

}
