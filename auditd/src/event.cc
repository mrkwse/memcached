/* -*- Mode: C++; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2015 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <sstream>
#include <string>
#include <cJSON.h>
#include "event.h"
#include "audit.h"

bool Event::process(Audit& audit) {
    // convert the event.payload into JSON
    cJSON *json_payload = cJSON_Parse(payload.c_str());
    if (json_payload == NULL) {
        Audit::log_error(JSON_PARSING_ERROR, payload.c_str());
        return false;
    }
    cJSON *timestamp_ptr = cJSON_GetObjectItem(json_payload, "timestamp");
    std::string timestamp;
    if (timestamp_ptr == NULL) {
        timestamp = Audit::generatetimestamp();
    } else {
        timestamp = std::string(timestamp_ptr->valuestring);
    }
    auto evt = audit.events.find(id);
    if (evt == audit.events.end()) {
        // it is an unknown event
        std::ostringstream convert;
        convert << id;
        Audit::log_error(UNKNOWN_EVENT_ERROR, convert.str().c_str());
        cJSON_Delete(json_payload);
        return false;
    }
    if (!evt->second->enabled) {
        // the event is not enabled so ignore event
        cJSON_Delete(json_payload);
        return true;
    }
    audit.auditfile.maybe_rotate_files();
    if (!audit.auditfile.ensure_open()) {
        Audit::log_error(OPEN_AUDITFILE_ERROR, NULL);
        cJSON_Delete(json_payload);
        return false;
    }
    if (!audit.auditfile.is_open_time_set()) {
        if (!audit.auditfile.set_auditfile_open_time(timestamp)) {
            Audit::log_error(SETTING_AUDITFILE_OPEN_TIME_ERROR,
                             timestamp.c_str());
            cJSON_Delete(json_payload);
            return false;
        }
    }

    cJSON_AddNumberToObject(json_payload, "id", id);
    cJSON_AddStringToObject(json_payload, "name", evt->second->name.c_str());
    cJSON_AddStringToObject(json_payload, "description", evt->second->description.c_str());

    bool success = audit.auditfile.write_event_to_disk(json_payload);

    // Release allocated resources
    cJSON_Delete(json_payload);

    if (success) {
        return true;
    } else {
        Audit::log_error(WRITE_EVENT_TO_DISK_ERROR, NULL);
        return false;
    }
}
