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
package org.traccar.model;

import org.traccar.storage.StorageName;

import java.util.Date;

@StorageName("tc_savekid_health")
public class SavekidHealth extends BaseModel {

    private long deviceId;

    public long getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(long deviceId) {
        this.deviceId = deviceId;
    }

    private Long positionId;

    public Long getPositionId() {
        return positionId;
    }

    public void setPositionId(Long positionId) {
        this.positionId = positionId;
    }

    private Date recordTime;

    public Date getRecordTime() {
        return recordTime;
    }

    public void setRecordTime(Date recordTime) {
        this.recordTime = recordTime;
    }

    private Integer heartRate;

    public Integer getHeartRate() {
        return heartRate;
    }

    public void setHeartRate(Integer heartRate) {
        this.heartRate = heartRate;
    }

    private Double bodyTemperature;

    public Double getBodyTemperature() {
        return bodyTemperature;
    }

    public void setBodyTemperature(Double bodyTemperature) {
        this.bodyTemperature = bodyTemperature;
    }

    private Integer steps;

    public Integer getSteps() {
        return steps;
    }

    public void setSteps(Integer steps) {
        this.steps = steps;
    }

    private Integer sleepMinutes;

    public Integer getSleepMinutes() {
        return sleepMinutes;
    }

    public void setSleepMinutes(Integer sleepMinutes) {
        this.sleepMinutes = sleepMinutes;
    }

    private Boolean sosActive;

    public Boolean getSosActive() {
        return sosActive;
    }

    public void setSosActive(Boolean sosActive) {
        this.sosActive = sosActive;
    }

    private Boolean sedentary;

    public Boolean getSedentary() {
        return sedentary;
    }

    public void setSedentary(Boolean sedentary) {
        this.sedentary = sedentary;
    }

    private Integer batteryLevel;

    public Integer getBatteryLevel() {
        return batteryLevel;
    }

    public void setBatteryLevel(Integer batteryLevel) {
        this.batteryLevel = batteryLevel;
    }
}
