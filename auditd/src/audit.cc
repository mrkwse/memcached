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

#include <algorithm>
#include <chrono>
#include <queue>
#include <map>
#include <sstream>
#include <iomanip>
#include <string>
#include <cstring>
#include <cJSON.h>
#include <fstream>
#include "auditd.h"
#include "audit.h"
#include "event.h"
#include "configureevent.h"
#include "eventdata.h"
#include "auditd_audit_events.h"

EXTENSION_LOGGER_DESCRIPTOR* Audit::logger = NULL;
std::string Audit::hostname;
void (*Audit::notify_io_complete)(const void *cookie,
                                  ENGINE_ERROR_CODE status);


void Audit::log_error(const ErrorCode return_code, const char *string) {
    switch (return_code) {
    case AUDIT_EXTENSION_DATA_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: audit extension data error");
        break;
    case FILE_ATTRIBUTES_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: attributes error on file %s: %s",
                    string, strerror(errno));
        break;
    case FILE_OPEN_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: open error on file %s: %s",
                    string, strerror(errno));
        break;
    case FILE_RENAME_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: rename error on file %s: %s",
                    string, strerror(errno));
        break;
    case FILE_REMOVE_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: remove error on file %s: %s",
                    string, strerror(errno));
        break;
    case MEMORY_ALLOCATION_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: memory allocation error: %s", string);
        break;
    case JSON_PARSING_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: JSON parsing error on string \"%s\"", string);
        break;
    case JSON_MISSING_DATA_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: JSON missing data error");
        break;
    case JSON_MISSING_OBJECT_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: JSON missing object error");
        break;
    case JSON_KEY_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: JSON key \"%s\" error", string);
        break;
    case JSON_ID_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: JSON eventid error");
        break;
    case JSON_UNKNOWN_FIELD_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: JSON unknown field error");
        break;
    case CB_CREATE_THREAD_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: cb create thread error");
        break;
    case EVENT_PROCESSING_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: event processing error");
        break;
    case PROCESSING_EVENT_FIELDS_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: processing events field error");
        break;
    case TIMESTAMP_MISSING_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: timestamp missing error");
        break;
    case TIMESTAMP_FORMAT_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: timestamp format error on string \"%s\"", string);
        break;
    case EVENT_ID_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: eventid error");
        break;
    case VERSION_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: audit version error");
        break;
    case VALIDATE_PATH_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: validate path \"%s\" error", string);
        break;
    case ROTATE_INTERVAL_BELOW_MIN_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: rotate_interval below minimum error");
        break;
    case ROTATE_INTERVAL_EXCEEDS_MAX_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: rotate_interval exceeds maximum error");
        break;
    case OPEN_AUDITFILE_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: error opening audit file");
        break;
    case SETTING_AUDITFILE_OPEN_TIME_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: error: setting auditfile open time = %s",
                    string);
        break;
    case WRITING_TO_DISK_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: writing to disk error: %s", string);
        break;
    case WRITE_EVENT_TO_DISK_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: error writing event to disk");
        break;
    case UNKNOWN_EVENT_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: error: unknown event %s", string);
        break;
    case CONFIG_INPUT_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: error reading config");
        break;
    case CONFIGURATION_ERROR:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: error performing configuration");
        break;
    case MISSING_AUDIT_EVENTS_FILE_ERROR:
        assert(string != NULL);
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: error: missing audit_event.json from \"%s\"",
                    string);
        break;
    case ROTATE_INTERVAL_SIZE_TOO_BIG:
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: error: rotation_size too big: %s",
                    string);
        break;
    default:
        assert(false);
    }
}


std::string Audit::load_file(const char *file) {
    std::ifstream myfile(file, std::ios::in | std::ios::binary);
    if (myfile.is_open()) {
        std::string str((std::istreambuf_iterator<char>(myfile)),
                        std::istreambuf_iterator<char>());
        myfile.close();
        return str;
    } else {
        Audit::log_error(FILE_OPEN_ERROR, file);
        std::string str;
        return str;
    }
}


bool Audit::is_timestamp_format_correct (std::string& str) {
    const char *data = str.c_str();
    if (str.length() < 19) {
        return false;
    } else if (isdigit(data[0]) && isdigit(data[1]) &&
        isdigit(data[2]) && isdigit(data[3]) &&
        data[4] == '-' &&
        isdigit(data[5]) && isdigit(data[6]) &&
        data[7] == '-' &&
        isdigit(data[8]) && isdigit(data[9]) &&
        data[10] == 'T' &&
        isdigit(data[11]) && isdigit(data[12]) &&
        data[13] == ':' &&
        isdigit(data[14]) && isdigit(data[15]) &&
        data[16] == ':' &&
        isdigit(data[17]) && isdigit(data[18])) {
        return true;
    }
    return false;
}


std::string Audit::generatetimestamp(void) {
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::chrono::system_clock::duration seconds_since_epoch =
    std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch());
    time_t now_t(std::chrono::system_clock::to_time_t(
                 std::chrono::system_clock::time_point(seconds_since_epoch)));
    std::chrono::milliseconds frac_of_second (
    std::chrono::duration_cast<std::chrono::milliseconds>(
                                  now.time_since_epoch() - seconds_since_epoch));
    struct tm utc_time;
    struct tm local_time;
#ifdef WIN32
    gmtime_s(&utc_time, &now_t);
    localtime_s(&local_time, &now_t);
#else
    gmtime_r(&now_t, &utc_time);
    localtime_r(&now_t, &local_time);
#endif
    time_t utc = mktime(&utc_time);
    time_t local = mktime(&local_time);
    double total_seconds_diff = difftime(local, utc);
    double total_minutes_diff = total_seconds_diff / 60;
    int32_t hours = (int32_t)(total_minutes_diff / 60);
    int32_t minutes = (int32_t)(total_minutes_diff) % 60;

    std::stringstream timestamp;
    timestamp << std::setw(4) << std::setfill('0') <<
    local_time.tm_year + 1900 << "-" <<
    std::setw(2) << std::setfill('0') << local_time.tm_mon+1 << "-" <<
    std::setw(2) << std::setfill('0') << local_time.tm_mday << "T" <<
    std::setw(2) << std::setfill('0') << local_time.tm_hour << ":" <<
    std::setw(2) << std::setfill('0') << local_time.tm_min << ":" <<
    std::setw(2) << std::setfill('0') << local_time.tm_sec << "." <<
    std::setw(3) << std::setfill('0') << std::setprecision(3) <<
    frac_of_second.count();

    if (total_seconds_diff == 0.0) {
        timestamp << "Z";
    } else if (total_seconds_diff < 0.0) {
        timestamp << "-"
                  << std::setw(2) << std::setfill('0') << abs(hours) << ":"
                  << std::setw(2) << std::setfill('0') << abs(minutes);
    } else {
        timestamp << "+"
                  << std::setw(2) << std::setfill('0') << hours << ":"
                  << std::setw(2) << std::setfill('0') << minutes;
    }

    return timestamp.str();
}


bool Audit::create_audit_event(uint32_t event_id, cJSON *payload) {
    // Add common fields to the audit event
    cJSON_AddStringToObject(payload, "timestamp", generatetimestamp().c_str());
    cJSON *real_userid = cJSON_CreateObject();
    cJSON_AddStringToObject(real_userid, "source", "internal");
    cJSON_AddStringToObject(real_userid, "user", "couchbase");
    cJSON_AddItemReferenceToObject(payload, "real_userid", real_userid);

    switch (event_id) {
        case AUDITD_AUDIT_CONFIGURED_AUDIT_DAEMON:
            if (config.auditd_enabled) {
                cJSON_AddTrueToObject(payload, "auditd_enabled");
            } else {
                cJSON_AddFalseToObject(payload, "auditd_enabled");
            }
            cJSON_AddStringToObject(payload, "descriptors_path", config.descriptors_path.c_str());
            cJSON_AddStringToObject(payload, "hostname", hostname.c_str());
            cJSON_AddStringToObject(payload, "log_path", config.log_path.c_str());
            cJSON_AddNumberToObject(payload, "rotate_interval", config.rotate_interval);
            cJSON_AddNumberToObject(payload, "version", 1.0);
            break;

        case AUDITD_AUDIT_SHUTTING_DOWN_AUDIT_DAEMON:
            break;

        default:
            log_error(EVENT_ID_ERROR, NULL);
            return false;
    }
    return true;
}


bool Audit::initialize_event_data_structures(cJSON *event_ptr) {
    if (event_ptr == NULL) {
        log_error(JSON_MISSING_DATA_ERROR, NULL);
        return false;
    }
    uint32_t eventid;
    bool set_eventid = false;
    EventData* eventdata;
    cJSON* values_ptr = event_ptr->child;
    if (values_ptr == NULL) {
        log_error(JSON_MISSING_DATA_ERROR, NULL);
        return false;
    }
    try {
        eventdata = new EventData;
    } catch (std::bad_alloc& ba) {
        log_error(MEMORY_ALLOCATION_ERROR, ba.what());
        return false;
    }
    while (values_ptr != NULL) {
        switch (values_ptr->type) {
            case cJSON_Number:
                if (strcmp(values_ptr->string, "id") == 0) {
                    eventid = values_ptr->valueint;
                    assert(eventid != 0);
                    set_eventid = true;
                } else {
                    log_error(JSON_KEY_ERROR,values_ptr->string);
                    return false;
                }
                break;
            case cJSON_String:
                if (strcmp(values_ptr->string, "name") == 0) {
                    eventdata->name = std::string(values_ptr->valuestring);
                } else if (strcmp(values_ptr->string, "description") == 0) {
                    eventdata->description = std::string(values_ptr->valuestring);
                } else {
                    log_error(JSON_KEY_ERROR, event_ptr->string);
                    return false;
                }
                break;
            case cJSON_True:
            case cJSON_False:
                if ((strcmp(values_ptr->string, "sync") != 0) &&
                    (strcmp(values_ptr->string, "enabled") != 0)) {
                    log_error(JSON_KEY_ERROR,values_ptr->string);
                    return false;
                }
                break;
            case cJSON_Object:
            case cJSON_Array:
                break;
            default:
                log_error(JSON_UNKNOWN_FIELD_ERROR, NULL);
                return false;
        }
        values_ptr = values_ptr->next;
    }
    if (set_eventid) {
        eventdata->sync = (std::find(config.sync.begin(),
                                     config.sync.end(), eventid) !=
                           config.sync.end()) ? true : false;
        eventdata->enabled = (std::find(config.disabled.begin(),
                                        config.disabled.end(), eventid)
                              != config.disabled.end()) ? false : true;
        events.insert(std::pair<uint32_t, EventData*>(eventid, eventdata));
    } else {
        Audit::log_error(JSON_ID_ERROR, NULL);
        return false;
    }
    return true;
}


bool Audit::process_module_data_structures(cJSON *module) {
    if (module == NULL) {
        log_error(JSON_MISSING_OBJECT_ERROR, NULL);
        return false;
    }
    while (module != NULL) {
        cJSON *mod_ptr = module->child;
        if (mod_ptr == NULL) {
            log_error(JSON_MISSING_DATA_ERROR, NULL);
            return false;
        }
        while (mod_ptr != NULL) {
            cJSON *event_ptr;
            switch (mod_ptr->type) {
                case cJSON_Number:
                case cJSON_String:
                    break;
                case cJSON_Array:
                    event_ptr = mod_ptr->child;
                    while (event_ptr != NULL) {
                        if (!initialize_event_data_structures(event_ptr)) {
                            return false;
                        }
                        event_ptr = event_ptr->next;
                    }
                    break;
                default:
                    log_error(JSON_UNKNOWN_FIELD_ERROR, NULL);
                    return false;
            }
            mod_ptr = mod_ptr->next;
        }
        module = module->next;
    }
    return true;
}


bool Audit::process_module_descriptor(cJSON *module_descriptor) {
    clear_events_map();
    while(module_descriptor != NULL) {
        switch (module_descriptor->type) {
            case cJSON_Number:
                break;
            case cJSON_Array:
                if (!process_module_data_structures(module_descriptor->child)) {
                    return false;
                }
                break;
            default:
                log_error(JSON_UNKNOWN_FIELD_ERROR, NULL);
                return false;
        }
        module_descriptor = module_descriptor->next;
    }
    return true;
}


bool Audit::configure(void) {
    bool is_enabled_before_reconfig = config.auditd_enabled;
    std::string configuration = load_file(configfile.c_str());
    if (configuration.empty()) {
        return false;
    }
    if (!config.initialize_config(configuration)) {
        return false;
    }
    if (!auditfile.is_open()) {
        if (!auditfile.cleanup_old_logfile(config.log_path)) {
            return false;
        }
    }
    std::stringstream audit_events_file;
    audit_events_file << config.descriptors_path;
    audit_events_file << DIRECTORY_SEPARATOR_CHARACTER << "audit_events.json";
    std::string str = load_file(audit_events_file.str().c_str());
    if (str.empty()) {
        return false;
    }
    cJSON *json_ptr = cJSON_Parse(str.c_str());
    if (json_ptr == NULL) {
        Audit::log_error(JSON_PARSING_ERROR, str.c_str());
        return false;
    }
    if (!process_module_descriptor(json_ptr->child)) {
        cJSON_Delete(json_ptr);
        return false;
    }
    cJSON_Delete(json_ptr);

    auditfile.reconfigure(config);

    // iterate through the events map and update the sync and enabled flags
    typedef std::map<uint32_t, EventData*>::iterator it_type;
    for(it_type iterator = events.begin(); iterator != events.end(); iterator++) {
        iterator->second->sync = (std::find(config.sync.begin(),
                                            config.sync.end(), iterator->first)
                                  != config.sync.end()) ? true : false;
        iterator->second->enabled = (std::find(config.disabled.begin(),
                                               config.disabled.end(), iterator->first)
                                     != config.disabled.end()) ? false : true;
    }
    // create event to say done reconfiguration
    if (is_enabled_before_reconfig || config.auditd_enabled) {
        cJSON *payload = cJSON_CreateObject();
        assert(payload != NULL);
        if (create_audit_event(AUDITD_AUDIT_CONFIGURED_AUDIT_DAEMON, payload)) {
            char *content = cJSON_Print(payload);
            assert(content != NULL);
            if (!add_to_filleventqueue(AUDITD_AUDIT_CONFIGURED_AUDIT_DAEMON,
                                        content, strlen(content))) {
                dropped_events++;
            }
            cJSON_Free(content);
        } else {
            dropped_events++;
        }
        cJSON_Delete(payload);
    }

    if (!config.auditd_enabled) {
        // Audit is disabled, ensure that the audit file is closed
        auditfile.close();
    }

    return true;
}


bool Audit::add_to_filleventqueue(const uint32_t event_id,
                                  const char *payload,
                                  const size_t length) {
    // @todo I think we should do full validation of the content
    //       in debug mode to ensure that developers actually fill
    //       in the correct fields.. if not we should add an
    //       event to the audit trail saying it is one in an illegal
    //       format (or missing fields)
    bool res;
    Event* new_event = new Event(event_id, payload, length);
    cb_mutex_enter(&producer_consumer_lock);
    assert(filleventqueue != NULL);
    if (filleventqueue->size() < max_audit_queue) {
        filleventqueue->push(new_event);
        cb_cond_broadcast(&events_arrived);
        res = true;
    } else {
        logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Audit: Dropping audit event %u: %s",
                    new_event->id, new_event->payload.c_str());
        dropped_events++;
        delete new_event;
        res = false;
    }
    cb_mutex_exit(&producer_consumer_lock);
    return res;
}


bool Audit::add_reconfigure_event(const void *cookie) {
    bool res;
    ConfigureEvent* new_event = new ConfigureEvent(cookie);
    cb_mutex_enter(&producer_consumer_lock);
    assert(filleventqueue != NULL);
    if (filleventqueue->size() < max_audit_queue) {
        filleventqueue->push(new_event);
        cb_cond_broadcast(&events_arrived);
        res = true;
    } else {
        Audit::logger->log(EXTENSION_LOG_WARNING, NULL,
                           "Audit: Dropping configure event: %s",
                           new_event->payload.c_str());
        dropped_events++;
        delete new_event;
        res = false;
    }
    cb_mutex_exit(&producer_consumer_lock);
    return res;
}


void Audit::clear_events_map(void) {
    typedef std::map<uint32_t, EventData*>::iterator it_type;
    for(it_type iterator = events.begin(); iterator != events.end(); iterator++) {
        assert(iterator->second != NULL);
        delete iterator->second;
    }
    events.clear();
}


void Audit::clear_events_queues(void) {
    while(!eventqueue1.empty()) {
        Event *event = eventqueue1.front();
        eventqueue1.pop();
        delete event;
    }
    while(!eventqueue2.empty()) {
        Event *event = eventqueue2.front();
        eventqueue2.pop();
        delete event;
    }
}


void Audit::clean_up(void) {
    clear_events_map();
    clear_events_queues();
}

std::string audit_generate_timestamp(void) {
    return Audit::generatetimestamp();
}
