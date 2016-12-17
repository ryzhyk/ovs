/*
 * Copyright (c) 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include <string.h>
#include "ovn/lib/ovn-log.h"

const char *
log_verdict_to_string(uint8_t verdict)
{
    if (verdict == LOG_VERDICT_ALLOW) {
        return "allow";
    } else if (verdict == LOG_VERDICT_DROP) {
        return "drop";
    } else if (verdict == LOG_VERDICT_REJECT) {
        return "reject";
    } else {
        return "<unknown>";
    }
}

const char *
log_severity_to_string(uint8_t severity)
{
    if (severity == LOG_SEVERITY_ALERT) {
        return "alert";
    } else if (severity == LOG_SEVERITY_WARNING) {
        return "warning";
    } else if (severity == LOG_SEVERITY_NOTICE) {
        return "notice";
    } else if (severity == LOG_SEVERITY_INFO) {
        return "info";
    } else if (severity == LOG_SEVERITY_DEBUG) {
        return "debug";
    } else {
        return "<unknown>";
    }
}

uint8_t
log_severity_from_string(const char *name)
{
    if (!strcmp(name, "alert")) {
        return LOG_SEVERITY_ALERT;
    } else if (!strcmp(name, "warning")) {
        return LOG_SEVERITY_WARNING;
    } else if (!strcmp(name, "notice")) {
        return LOG_SEVERITY_NOTICE;
    } else if (!strcmp(name, "info")) {
        return LOG_SEVERITY_INFO;
    } else if (!strcmp(name, "debug")) {
        return LOG_SEVERITY_DEBUG;
    } else {
        return UINT8_MAX;
    }
}
