/*
 * Copyright 2025 SaveKID
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.handler;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.model.Position;
import org.traccar.model.SavekidHealth;
import org.traccar.storage.Storage;
import org.traccar.storage.query.Columns;
import org.traccar.storage.query.Request;

import java.util.Date;
import java.util.Map;

@Singleton
public class SavekidHealthHandler extends BasePositionHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(SavekidHealthHandler.class);

    private final Storage storage;

    @Inject
    public SavekidHealthHandler(Storage storage) {
        this.storage = storage;
    }

    private SavekidHealth buildHealthRecord(Position position) {
        Map<String, Object> attributes = position.getAttributes();

        Integer heartRate = attributes.containsKey(Position.KEY_HEART_RATE)
                ? position.getInteger(Position.KEY_HEART_RATE) : null;
        Double bodyTemperature = attributes.containsKey(Position.KEY_BODY_TEMPERATURE)
                ? position.getDouble(Position.KEY_BODY_TEMPERATURE) : null;
        Integer steps = attributes.containsKey(Position.KEY_STEPS) ? position.getInteger(Position.KEY_STEPS) : null;
        Integer sleepMinutes = attributes.containsKey(Position.KEY_SLEEP_MINUTES)
                ? position.getInteger(Position.KEY_SLEEP_MINUTES) : null;
        Boolean sosActive = attributes.containsKey(Position.KEY_SOS_ACTIVE)
                ? position.getBoolean(Position.KEY_SOS_ACTIVE) : null;
        Boolean sedentary = attributes.containsKey(Position.KEY_SEDENTARY)
                ? position.getBoolean(Position.KEY_SEDENTARY) : null;
        Integer batteryLevel = attributes.containsKey(Position.KEY_BATTERY_LEVEL)
                ? position.getInteger(Position.KEY_BATTERY_LEVEL) : null;

        if (heartRate == null && bodyTemperature == null && steps == null
                && sleepMinutes == null && sosActive == null && sedentary == null && batteryLevel == null) {
            return null;
        }

        SavekidHealth health = new SavekidHealth();
        health.setDeviceId(position.getDeviceId());
        health.setPositionId(position.getId());

        Date recordTime = position.getFixTime();
        if (recordTime == null) {
            recordTime = position.getDeviceTime();
        }
        if (recordTime == null) {
            recordTime = position.getServerTime();
        }
        health.setRecordTime(recordTime);

        health.setHeartRate(heartRate);
        health.setBodyTemperature(bodyTemperature);
        health.setSteps(steps);
        health.setSleepMinutes(sleepMinutes);
        health.setSosActive(sosActive);
        health.setSedentary(sedentary);
        health.setBatteryLevel(batteryLevel);

        return health;
    }

    @Override
    public void onPosition(Position position, Callback callback) {
        try {
            SavekidHealth health = buildHealthRecord(position);
            if (health != null) {
                storage.addObject(health, new Request(new Columns.Exclude("id")));
            }
        } catch (Exception error) {
            LOGGER.warn("Failed to store SaveKID health data", error);
        }

        callback.processed(false);
    }
}
