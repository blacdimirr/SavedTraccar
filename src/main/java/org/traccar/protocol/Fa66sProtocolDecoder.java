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
package org.traccar.protocol;

import io.netty.channel.Channel;
import org.traccar.BaseProtocolDecoder;
import org.traccar.Protocol;
import org.traccar.helper.DateBuilder;
import org.traccar.model.Position;
import org.traccar.session.DeviceSession;

import java.net.SocketAddress;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Fa66sProtocolDecoder extends BaseProtocolDecoder {

    public Fa66sProtocolDecoder(Protocol protocol) {
        super(protocol);
    }

    private static Double parseDouble(String value) {
        if (value != null) {
            try {
                return Double.parseDouble(value);
            } catch (NumberFormatException ignored) {
            }
        }
        return null;
    }

    private static Integer parseInteger(String value) {
        if (value != null) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException ignored) {
            }
        }
        return null;
    }

    private static Boolean parseBoolean(String value) {
        if (value != null) {
            return "1".equals(value) || Boolean.parseBoolean(value);
        }
        return null;
    }

    private Date parseTime(String value) {
        if (value != null) {
            var cleaned = value.replaceAll("[^0-9]", "");
            if (cleaned.length() == 12 || cleaned.length() == 14) {
                try {
                    int offset = cleaned.length() == 12 ? 2 : 4;
                    int year = Integer.parseInt(cleaned.substring(0, offset));
                    if (offset == 2) {
                        year += 2000;
                    }
                    int month = Integer.parseInt(cleaned.substring(offset, offset + 2));
                    int day = Integer.parseInt(cleaned.substring(offset + 2, offset + 4));
                    int hour = Integer.parseInt(cleaned.substring(offset + 4, offset + 6));
                    int minute = Integer.parseInt(cleaned.substring(offset + 6, offset + 8));
                    int second = Integer.parseInt(cleaned.substring(offset + 8, offset + 10));
                    return new DateBuilder()
                            .setDate(year, month, day)
                            .setTime(hour, minute, second)
                            .getDate();
                } catch (Exception ignored) {
                }
            }
        }
        return null;
    }

    private Map<String, String> parseKeyValues(String sentence) {
        Map<String, String> result = new HashMap<>();
        for (String part : sentence.split("[;|]")) {
            var token = part.trim();
            int equals = token.indexOf('=');
            if (equals > 0) {
                result.put(token.substring(0, equals).toLowerCase(), token.substring(equals + 1));
            }
        }
        return result;
    }

    @Override
    protected Object decode(Channel channel, SocketAddress remoteAddress, Object msg) throws Exception {

        String sentence = ((String) msg).trim();
        if (sentence.isEmpty()) {
            return null;
        }

        Map<String, String> keyValues = parseKeyValues(sentence);

        String imei = keyValues.getOrDefault("imei", keyValues.get("id"));
        String[] parts = sentence.split(",");
        if (imei == null && parts.length > 1 && parts[0].toUpperCase().startsWith("FA66")) {
            imei = parts[1];
        }

        DeviceSession deviceSession = getDeviceSession(channel, remoteAddress, imei);
        if (deviceSession == null) {
            return null;
        }

        Position position = new Position(getProtocolName());
        position.setDeviceId(deviceSession.getDeviceId());

        Double latitude = parseDouble(keyValues.getOrDefault("lat", keyValues.get("latitude")));
        Double longitude = parseDouble(keyValues.getOrDefault("lon", keyValues.get("longitude")));
        Double altitude = parseDouble(keyValues.get("alt"));
        Double speed = parseDouble(keyValues.get("speed"));
        Double course = parseDouble(keyValues.get("course"));
        Date time = parseTime(keyValues.getOrDefault("time", keyValues.get("timestamp")));

        if (latitude == null && parts.length >= 4) {
            latitude = parseDouble(parts[2]);
            longitude = parseDouble(parts[3]);
        }
        if (speed == null && parts.length >= 6) {
            speed = parseDouble(parts[4]);
            course = parseDouble(parts[5]);
        }
        if (altitude == null && parts.length >= 7) {
            altitude = parseDouble(parts[6]);
        }
        if (time == null && parts.length >= 3) {
            time = parseTime(parts[parts.length - 1]);
        }

        if (latitude != null && longitude != null) {
            position.setValid(true);
            position.setLatitude(latitude);
            position.setLongitude(longitude);
            position.setAltitude(altitude != null ? altitude : 0);
            position.setSpeed(speed != null ? speed.floatValue() : 0);
            position.setCourse(course != null ? course.floatValue() : 0);
        } else {
            getLastLocation(position, null);
        }

        if (time != null) {
            position.setTime(time);
        }

        Integer heartRate = parseInteger(keyValues.getOrDefault("hr", keyValues.get("heartrate")));
        if (heartRate == null && parts.length >= 9) {
            heartRate = parseInteger(parts[8]);
        }
        if (heartRate != null) {
            position.set(Position.KEY_HEART_RATE, heartRate);
        }

        Double temperature = parseDouble(keyValues.getOrDefault("temp", keyValues.get("temperature")));
        if (temperature == null && parts.length >= 10) {
            temperature = parseDouble(parts[9]);
        }
        if (temperature != null) {
            position.set(Position.KEY_BODY_TEMPERATURE, temperature);
        }

        Integer steps = parseInteger(keyValues.getOrDefault("steps", keyValues.get("walk")));
        if (steps == null && parts.length >= 11) {
            steps = parseInteger(parts[10]);
        }
        if (steps != null) {
            position.set(Position.KEY_STEPS, steps);
        }

        Integer sleepMinutes = parseInteger(keyValues.getOrDefault("sleep", keyValues.get("sleepmin")));
        if (sleepMinutes == null && parts.length >= 12) {
            sleepMinutes = parseInteger(parts[11]);
        }
        if (sleepMinutes != null) {
            position.set(Position.KEY_SLEEP_MINUTES, sleepMinutes);
        }

        Boolean sos = parseBoolean(keyValues.getOrDefault("sos", keyValues.get("alert")));
        if (sos == null && parts.length >= 13) {
            sos = parseBoolean(parts[12]);
        }
        if (sos != null) {
            position.set(Position.KEY_SOS_ACTIVE, sos);
            if (sos) {
                position.set(Position.KEY_ALARM, Position.ALARM_SOS);
            }
        }

        Boolean sedentary = parseBoolean(keyValues.getOrDefault("sed", keyValues.get("sedentary")));
        if (sedentary == null && parts.length >= 14) {
            sedentary = parseBoolean(parts[13]);
        }
        if (sedentary != null) {
            position.set(Position.KEY_SEDENTARY, sedentary);
        }

        Integer battery = parseInteger(keyValues.getOrDefault("bat", keyValues.get("battery")));
        if (battery == null && parts.length >= 8) {
            battery = parseInteger(parts[7]);
        }
        if (battery != null) {
            position.set(Position.KEY_BATTERY_LEVEL, battery);
        }

        return position;
    }
}
