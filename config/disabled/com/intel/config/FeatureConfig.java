/*
 * Copyright (C) 2013 Intel Corporation
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

package com.intel.config;

public class FeatureConfig {
    // Suppress default constructor for non instantiability
    private FeatureConfig() { throw new AssertionError(); }

    // Set to true to enable the feature or false to remove it at compilation time
    public static final boolean INTEL_FEATURE_ARKHAM = false;
}

